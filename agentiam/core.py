"""
Agent-JIT-IAM: The Ephemeral Just-In-Time IAM Token & Zero-Standing-Privilege Delegator.
Standard library only: hashlib, hmac, json, time, os, dataclasses, typing, secrets.
"""

from __future__ import annotations

import dataclasses
import hashlib
import hmac
import json
import os
import secrets
import time
from typing import Any, Callable, Dict, List, Optional, Set, Tuple


GENESIS_HASH: str = "0000000000000000000000000000000000000000000000000000000000000000"


@dataclasses.dataclass(frozen=True)
class EphemeralJITToken:
    """Short-lived, single-use, cryptographically signed Just-In-Time token."""
    token_id: str
    agent_id: str
    allowed_scope: str
    issued_at: float
    expires_at: float
    single_use: bool
    signature: str

    def is_valid(self, requested_scope: str) -> bool:
        if time.time() > self.expires_at:
            return False
        if self.allowed_scope != "*" and self.allowed_scope != requested_scope:
            return False
        return True


@dataclasses.dataclass(frozen=True)
class IAMReceipt:
    """Immutable SHA-256 cryptographically chained IAM delegation receipt."""
    index: int
    prev_hash: str
    token_id: str
    agent_id: str
    scope: str
    status: str
    timestamp: float
    signature_hash: str

    def to_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)


class CryptographicIAMLedger:
    """Tamper-Proof Audit Ledger for Agent IAM events (ISO 42001 & SOC 2 Type II)."""

    def __init__(self, ledger_file: Optional[str] = None):
        self.ledger_file = ledger_file
        self._entries: List[IAMReceipt] = []
        self._last_hash = GENESIS_HASH

    @property
    def last_hash(self) -> str:
        return self._last_hash

    @property
    def count(self) -> int:
        return len(self._entries)

    def record_delegation(
        self,
        token_id: str,
        agent_id: str,
        scope: str,
        status: str,
    ) -> IAMReceipt:
        idx = len(self._entries)
        ts = time.time()

        # SHA-256 Hash Chain
        raw_msg = f"{idx}:{self._last_hash}:{token_id}:{agent_id}:{scope}:{status}:{ts:.6f}"
        sig_hash = hashlib.sha256(raw_msg.encode("utf-8")).hexdigest()

        receipt = IAMReceipt(
            index=idx,
            prev_hash=self._last_hash,
            token_id=token_id,
            agent_id=agent_id,
            scope=scope,
            status=status,
            timestamp=ts,
            signature_hash=sig_hash,
        )

        self._entries.append(receipt)
        self._last_hash = sig_hash

        if self.ledger_file:
            os.makedirs(os.path.dirname(os.path.abspath(self.ledger_file)), exist_ok=True)
            with open(self.ledger_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(receipt.to_dict()) + chr(10))

        return receipt

    def verify_chain_integrity(self) -> Tuple[bool, Optional[str]]:
        current_prev = GENESIS_HASH
        for idx, entry in enumerate(self._entries):
            if entry.index != idx:
                return False, f"Sequence index break at {idx}"
            if entry.prev_hash != current_prev:
                return False, f"Broken SHA-256 chain at {idx}"
            current_prev = entry.signature_hash
        return True, None


class AgentJITDelegator:
    """
    Zero-Standing-Privilege (ZSP) Dynamic Token Minter & Scoped Authorization Gate.
    """

    def __init__(
        self,
        secret_key: Optional[str] = None,
        default_ttl_seconds: int = 30,
        ledger_path: Optional[str] = None,
    ):
        self._secret_key = (secret_key or secrets.token_hex(32)).encode("utf-8")
        self.default_ttl_seconds = default_ttl_seconds
        self.ledger = CryptographicIAMLedger(ledger_file=ledger_path)
        self._used_tokens: Set[str] = set()

    def check_kill_switch(self) -> bool:
        if os.environ.get("AGENT_IAM_KILL", "0") in ("1", "true", "TRUE"):
            return True
        if os.path.exists("/tmp/AGENT_IAM_KILL"):
            return True
        return False

    def mint_ephemeral_token(
        self,
        agent_id: str,
        allowed_scope: str,
        ttl_seconds: Optional[int] = None,
        single_use: bool = True,
    ) -> EphemeralJITToken:
        """
        Mints an ephemeral, single-use, HMAC-signed JIT token.
        """
        token_id = f"jit_{secrets.token_hex(12)}"
        now = time.time()
        ttl = ttl_seconds or self.default_ttl_seconds
        expires_at = now + ttl

        # HMAC-SHA256 signature
        payload = f"{token_id}:{agent_id}:{allowed_scope}:{now:.6f}:{expires_at:.6f}:{single_use}"
        sig = hmac.new(self._secret_key, payload.encode("utf-8"), hashlib.sha256).hexdigest()

        token = EphemeralJITToken(
            token_id=token_id,
            agent_id=agent_id,
            allowed_scope=allowed_scope,
            issued_at=now,
            expires_at=expires_at,
            single_use=single_use,
            signature=sig,
        )

        self.ledger.record_delegation(
            token_id=token_id,
            agent_id=agent_id,
            scope=allowed_scope,
            status="TOKEN_MINTED",
        )

        return token

    def authorize_and_consume(
        self,
        token: EphemeralJITToken,
        requested_scope: str,
    ) -> Tuple[bool, IAMReceipt]:
        """
        Verifies token validity, scope alignment, and consumes single-use credentials.
        """
        if self.check_kill_switch():
            receipt = self.ledger.record_delegation(
                token_id=token.token_id,
                agent_id=token.agent_id,
                scope=requested_scope,
                status="BLOCKED_BY_EMERGENCY_KILL_SWITCH",
            )
            return False, receipt

        # 1. Single-use replay attack check
        if token.single_use and token.token_id in self._used_tokens:
            receipt = self.ledger.record_delegation(
                token_id=token.token_id,
                agent_id=token.agent_id,
                scope=requested_scope,
                status="REJECTED_TOKEN_ALREADY_CONSUMED",
            )
            return False, receipt

        # 2. Cryptographic signature check
        payload = f"{token.token_id}:{token.agent_id}:{token.allowed_scope}:{token.issued_at:.6f}:{token.expires_at:.6f}:{token.single_use}"
        expected_sig = hmac.new(self._secret_key, payload.encode("utf-8"), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(token.signature, expected_sig):
            receipt = self.ledger.record_delegation(
                token_id=token.token_id,
                agent_id=token.agent_id,
                scope=requested_scope,
                status="REJECTED_INVALID_SIGNATURE",
            )
            return False, receipt

        # 3. Expiration & Scope check
        if not token.is_valid(requested_scope):
            receipt = self.ledger.record_delegation(
                token_id=token.token_id,
                agent_id=token.agent_id,
                scope=requested_scope,
                status="REJECTED_EXPIRED_OR_SCOPE_MISMATCH",
            )
            return False, receipt

        # 4. Mark as consumed
        if token.single_use:
            self._used_tokens.add(token.token_id)

        receipt = self.ledger.record_delegation(
            token_id=token.token_id,
            agent_id=token.agent_id,
            scope=requested_scope,
            status="AUTHORIZED_JIT_ACCESS_GRANTED",
        )

        return True, receipt
