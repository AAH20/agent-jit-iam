# Aegis Agent JIT IAM

Deterministic, credentialless authorization for autonomous workloads.

The broker lets an agent request an external API operation without possessing a
reusable credential. A trusted OpenShell-style proxy evaluates a signed,
workload-bound capability and attaches or derives the provider credential only
after authorization succeeds.

```text
agent -> uncredentialed request -> Aegis capability check -> credential proxy -> provider
                                      | deny                  | allow
                                      +---- signed receipt ---+
```

No model call occurs in the authorization path. The reference implementation is
Python standard-library only.

## Security properties

- SPIFFE/OpenShell workload binding prevents transfer between sandboxes.
- Provider, method, path and request facts implement semantic least privilege.
- Explicit deny rules precede allow rules.
- Signed canonical capability documents detect mutation.
- Child delegation cannot add operations, uses, lifetime or providers.
- Atomic SQLite counters survive restarts and prevent replay.
- Hash-linked EffectProof-compatible receipts bind decisions to request digests.
- Real provider credentials remain outside the agent process.

## GitHub vertical

```python
from agentiam import AuthorityBroker, ProviderOperation

broker = AuthorityBroker(b"replace-with-32-byte-secret........")
capability = broker.issue(
    subject="did:key:worker-agent",
    workload="spiffe://openshell/sandbox/8f21",
    provider="github",
    operations=[ProviderOperation(
        "POST",
        "/repos/AAH20/project/git/refs",
        {"ref_prefix": "refs/heads/aegis/"},
    )],
    denied_paths=[
        "/repos/*/*/actions/secrets/*",
        "/repos/*/*/branches/main/*",
    ],
    ttl_seconds=60,
    max_uses=1,
)

receipt = broker.authorize(
    capability,
    workload="spiffe://openshell/sandbox/8f21",
    provider="github",
    method="POST",
    path="/repos/AAH20/project/git/refs",
    facts={"ref": "refs/heads/aegis/fix-123"},
)
assert receipt.decision == "ALLOW"
```

The trusted proxy must forward only on `ALLOW`. The broker never accepts a
credential and deliberately performs no network I/O.

## Threat model

The agent and its descendants are untrusted. The proxy, broker signing key,
replay database, clock and workload-identity assertion are trusted. Deployments
must derive `workload` from the sandbox/SPIFFE connection, never an
agent-controlled header. HMAC is the compact reference signer; multi-host
deployments should put signing behind KMS/HSM or add an asymmetric signer.

Path `*` matches exactly one segment. Policies must name deeper resources
explicitly, preventing a narrow-looking rule from recursively authorizing an
unknown API subtree.

## Test

```bash
python3 -m unittest discover -s tests -v
```

The suite covers allowed operations, persistent replay prevention, workload
theft, signature mutation, explicit denial, semantic branch constraints,
expiration and delegation widening.

## OpenShell alignment

- [#682: cryptographic agent identity binding](https://github.com/NVIDIA/OpenShell/issues/682)
- [#896: enhanced provider management](https://github.com/NVIDIA/OpenShell/issues/896)
- [#1931: credential drivers](https://github.com/NVIDIA/OpenShell/issues/1931)
- [#1665: SPIFFE workload identity provider](https://github.com/NVIDIA/OpenShell/issues/1665)

The original `AgentJITDelegator` string-scope API remains available for compatibility.

## Author

Ahmed Hassan — [GitHub](https://github.com/AAH20) · [A2Z SOC](https://a2zsoc.com)
