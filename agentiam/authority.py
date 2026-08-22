"""Deterministic, credentialless authority enforcement for autonomous workloads.

The broker evaluates an uncredentialed HTTP request. A trusted proxy may attach a
provider credential only after :meth:`AuthorityBroker.authorize` succeeds.
"""

from __future__ import annotations

import dataclasses
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import threading
import time
from typing import Any, Dict, Iterable, Mapping, Optional, Sequence, Tuple


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def _digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical(value)).hexdigest()


def _match(pattern: str, value: str) -> bool:
    expression = re.escape(pattern).replace(r"\*", "[^/]+")
    return re.fullmatch(expression, value) is not None


@dataclasses.dataclass(frozen=True)
class ProviderOperation:
    method: str
    path: str
    constraints: Mapping[str, Any] = dataclasses.field(default_factory=dict)

    def permits(self, method: str, path: str, facts: Mapping[str, Any]) -> bool:
        if self.method != "*" and self.method.upper() != method.upper():
            return False
        if not _match(self.path, path):
            return False
        for name, expected in self.constraints.items():
            actual = facts.get(name)
            if name.endswith("_prefix"):
                source_name = name[: -len("_prefix")]
                actual = facts.get(source_name)
                if not isinstance(actual, str) or not actual.startswith(str(expected)):
                    return False
            elif isinstance(expected, list):
                if actual not in expected:
                    return False
            elif actual != expected:
                return False
        return True

    def to_dict(self) -> Dict[str, Any]:
        return {"method": self.method.upper(), "path": self.path, "constraints": dict(self.constraints)}


@dataclasses.dataclass(frozen=True)
class Capability:
    capability_id: str
    subject: str
    workload: str
    provider: str
    operations: Tuple[ProviderOperation, ...]
    denied_paths: Tuple[str, ...]
    issued_at: int
    expires_at: int
    max_uses: int
    nonce: str
    issuer: str
    parent_digest: Optional[str] = None
    signature: str = ""

    def unsigned(self) -> Dict[str, Any]:
        return {
            "capability_id": self.capability_id,
            "subject": self.subject,
            "workload": self.workload,
            "provider": self.provider,
            "operations": [operation.to_dict() for operation in self.operations],
            "denied_paths": list(self.denied_paths),
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "max_uses": self.max_uses,
            "nonce": self.nonce,
            "issuer": self.issuer,
            "parent_digest": self.parent_digest,
        }

    @property
    def digest(self) -> str:
        return _digest(self.unsigned())

    def to_dict(self) -> Dict[str, Any]:
        return {**self.unsigned(), "signature": self.signature}


@dataclasses.dataclass(frozen=True)
class EffectReceipt:
    decision: str
    reason: str
    capability_digest: str
    subject: str
    workload: str
    provider: str
    method: str
    path: str
    request_digest: str
    timestamp: int
    previous_receipt: str
    broker_signature: str
    receipt_digest: str


class ReplayStore:
    """Atomic use counters. SQLite permits safe sharing across proxy processes."""

    def __init__(self, path: str = ":memory:"):
        self._db = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self._lock = threading.Lock()
        self._db.execute("CREATE TABLE IF NOT EXISTS uses (digest TEXT PRIMARY KEY, count INTEGER NOT NULL)")

    def consume(self, digest: str, maximum: int) -> bool:
        with self._lock, self._db:
            row = self._db.execute("SELECT count FROM uses WHERE digest = ?", (digest,)).fetchone()
            count = int(row[0]) if row else 0
            if count >= maximum:
                return False
            self._db.execute(
                "INSERT INTO uses(digest, count) VALUES(?, 1) "
                "ON CONFLICT(digest) DO UPDATE SET count = count + 1",
                (digest,),
            )
            return True


class AuthorityBroker:
    def __init__(self, signing_key: bytes, issuer: str = "aegis-authority", replay_db: str = ":memory:"):
        if len(signing_key) < 32:
            raise ValueError("signing_key must contain at least 32 bytes")
        self._key = signing_key
        self.issuer = issuer
        self.replays = ReplayStore(replay_db)
        self._receipt_head = "sha256:" + "0" * 64
        self._receipt_lock = threading.Lock()

    def _sign(self, payload: Mapping[str, Any]) -> str:
        return "hmac-sha256:" + hmac.new(self._key, _canonical(payload), hashlib.sha256).hexdigest()

    def issue(
        self,
        *,
        subject: str,
        workload: str,
        provider: str,
        operations: Sequence[ProviderOperation],
        denied_paths: Iterable[str] = (),
        ttl_seconds: int = 60,
        max_uses: int = 1,
        parent: Optional[Capability] = None,
        now: Optional[int] = None,
    ) -> Capability:
        if not operations or ttl_seconds <= 0 or max_uses <= 0:
            raise ValueError("operations, positive TTL, and positive max_uses are required")
        issued = int(time.time() if now is None else now)
        cap = Capability(
            capability_id="cap_" + secrets.token_hex(12), subject=subject, workload=workload,
            provider=provider, operations=tuple(operations), denied_paths=tuple(denied_paths),
            issued_at=issued, expires_at=issued + ttl_seconds, max_uses=max_uses,
            nonce=secrets.token_urlsafe(18), issuer=self.issuer,
            parent_digest=parent.digest if parent else None,
        )
        if parent is not None:
            self._validate_delegation(parent, cap)
        return dataclasses.replace(cap, signature=self._sign(cap.unsigned()))

    def _validate_delegation(self, parent: Capability, child: Capability) -> None:
        if not self.verify(parent):
            raise ValueError("parent capability signature is invalid")
        if parent.provider != child.provider or child.expires_at > parent.expires_at:
            raise ValueError("delegation widens provider or lifetime")
        if child.max_uses > parent.max_uses:
            raise ValueError("delegation widens use count")
        for child_op in child.operations:
            if not any(parent_op.method in ("*", child_op.method) and _match(parent_op.path, child_op.path)
                       for parent_op in parent.operations):
                raise ValueError("delegation contains operation absent from parent")

    def verify(self, capability: Capability) -> bool:
        return capability.issuer == self.issuer and hmac.compare_digest(
            capability.signature, self._sign(capability.unsigned())
        )

    def verify_receipt(self, receipt: EffectReceipt) -> bool:
        body = dataclasses.asdict(receipt)
        receipt_digest = body.pop("receipt_digest")
        signature = body.pop("broker_signature")
        return hmac.compare_digest(signature, self._sign(body)) and hmac.compare_digest(
            receipt_digest, _digest({**body, "broker_signature": signature})
        )

    def authorize(
        self, capability: Capability, *, workload: str, provider: str, method: str,
        path: str, facts: Optional[Mapping[str, Any]] = None, now: Optional[int] = None,
    ) -> EffectReceipt:
        timestamp = int(time.time() if now is None else now)
        facts = facts or {}
        reason = "authorized"
        allowed = True
        if not self.verify(capability):
            allowed, reason = False, "invalid_signature"
        elif capability.workload != workload:
            allowed, reason = False, "workload_mismatch"
        elif capability.provider != provider:
            allowed, reason = False, "provider_mismatch"
        elif timestamp < capability.issued_at or timestamp >= capability.expires_at:
            allowed, reason = False, "capability_expired_or_not_yet_valid"
        elif any(_match(pattern, path) for pattern in capability.denied_paths):
            allowed, reason = False, "explicitly_denied_path"
        elif not any(operation.permits(method, path, facts) for operation in capability.operations):
            allowed, reason = False, "operation_not_permitted"
        elif not self.replays.consume(capability.digest, capability.max_uses):
            allowed, reason = False, "use_limit_exceeded"
        return self._receipt(capability, allowed, reason, provider, method, path, facts, timestamp)

    def _receipt(self, cap: Capability, allowed: bool, reason: str, provider: str,
                 method: str, path: str, facts: Mapping[str, Any], timestamp: int) -> EffectReceipt:
        with self._receipt_lock:
            body = {
                "decision": "ALLOW" if allowed else "DENY", "reason": reason,
                "capability_digest": cap.digest, "subject": cap.subject, "workload": cap.workload,
                "provider": provider, "method": method.upper(), "path": path,
                "request_digest": _digest({"method": method.upper(), "path": path, "facts": dict(facts)}),
                "timestamp": timestamp, "previous_receipt": self._receipt_head,
            }
            broker_signature = self._sign(body)
            receipt_digest = _digest({**body, "broker_signature": broker_signature})
            self._receipt_head = receipt_digest
            return EffectReceipt(**body, broker_signature=broker_signature, receipt_digest=receipt_digest)
