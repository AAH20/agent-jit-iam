import tempfile
import unittest

from agentiam import AuthorityBroker, ProviderOperation


class AuthorityBrokerTests(unittest.TestCase):
    def setUp(self):
        self.now = 1_800_000_000
        self.broker = AuthorityBroker(b"a" * 32)
        self.operation = ProviderOperation(
            "POST", "/repos/AAH20/project/git/refs", {"ref_prefix": "refs/heads/aegis/"}
        )
        self.capability = self.broker.issue(
            subject="did:key:worker", workload="spiffe://openshell/sandbox/8f21",
            provider="github", operations=[self.operation],
            denied_paths=["/repos/*/*/actions/*", "/repos/*/*/branches/main/*"],
            ttl_seconds=60, max_uses=1, now=self.now,
        )

    def authorize(self, capability=None, **overrides):
        request = dict(
            capability=capability or self.capability,
            workload="spiffe://openshell/sandbox/8f21", provider="github", method="POST",
            path="/repos/AAH20/project/git/refs",
            facts={"ref": "refs/heads/aegis/fix-123"}, now=self.now + 1,
        )
        request.update(overrides)
        return self.broker.authorize(**request)

    def test_allows_bound_semantic_operation_then_blocks_replay(self):
        allowed = self.authorize()
        self.assertEqual(allowed.decision, "ALLOW")
        self.assertTrue(self.broker.verify_receipt(allowed))
        replay = self.authorize()
        self.assertEqual((replay.decision, replay.reason), ("DENY", "use_limit_exceeded"))

    def test_rejects_branch_constraint(self):
        receipt = self.authorize(facts={"ref": "refs/heads/main"})
        self.assertEqual((receipt.decision, receipt.reason), ("DENY", "operation_not_permitted"))

    def test_explicit_deny_precedes_broad_allow(self):
        cap = self.broker.issue(
            subject="agent", workload="workload", provider="github",
            operations=[ProviderOperation("*", "/repos/*/*/actions/secrets/*")],
            denied_paths=["/repos/*/*/actions/secrets/*"], now=self.now,
        )
        receipt = self.broker.authorize(
            cap, workload="workload", provider="github", method="PUT",
            path="/repos/AAH20/project/actions/secrets/DEPLOY", now=self.now + 1,
        )
        self.assertEqual(receipt.reason, "explicitly_denied_path")

    def test_capability_is_non_transferable(self):
        receipt = self.authorize(workload="spiffe://openshell/sandbox/attacker")
        self.assertEqual(receipt.reason, "workload_mismatch")

    def test_signature_tampering_fails(self):
        import dataclasses
        forged = dataclasses.replace(self.capability, max_uses=999)
        self.assertEqual(self.authorize(capability=forged).reason, "invalid_signature")

    def test_child_delegation_cannot_widen_authority(self):
        child = self.broker.issue(
            subject="child", workload="child-workload", provider="github",
            operations=[self.operation], ttl_seconds=30, parent=self.capability, now=self.now,
        )
        self.assertEqual(child.parent_digest, self.capability.digest)
        with self.assertRaisesRegex(ValueError, "operation absent"):
            self.broker.issue(
                subject="child", workload="child-workload", provider="github",
                operations=[ProviderOperation("DELETE", "/repos/AAH20/project")],
                ttl_seconds=30, parent=self.capability, now=self.now,
            )

    def test_sqlite_replay_state_survives_broker_restart(self):
        with tempfile.NamedTemporaryFile() as db:
            first = AuthorityBroker(b"b" * 32, replay_db=db.name)
            cap = first.issue(subject="a", workload="w", provider="github",
                              operations=[ProviderOperation("GET", "/user")], now=self.now)
            self.assertEqual(first.authorize(cap, workload="w", provider="github", method="GET",
                                             path="/user", now=self.now + 1).decision, "ALLOW")
            second = AuthorityBroker(b"b" * 32, replay_db=db.name)
            self.assertEqual(second.authorize(cap, workload="w", provider="github", method="GET",
                                              path="/user", now=self.now + 2).reason, "use_limit_exceeded")


if __name__ == "__main__":
    unittest.main()
