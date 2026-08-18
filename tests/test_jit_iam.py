import unittest
import os
import sys
import time

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from agentiam.core import AgentJITDelegator, GENESIS_HASH


class TestAgentJITIAM(unittest.TestCase):
    def setUp(self):
        self.delegator = AgentJITDelegator(default_ttl_seconds=5)

    def test_ephemeral_token_minting_and_authorization(self):
        # 1. Mint 5-second JIT token scoped to 'dynamodb:read'
        token = self.delegator.mint_ephemeral_token(
            agent_id='agent_support_bot',
            allowed_scope='dynamodb:read',
            ttl_seconds=5,
            single_use=True,
        )
        self.assertIsNotNone(token)
        self.assertEqual(token.allowed_scope, 'dynamodb:read')

        # 2. Authorize legitimate scope
        allowed, receipt = self.delegator.authorize_and_consume(token, 'dynamodb:read')
        self.assertTrue(allowed)
        self.assertEqual(receipt.status, 'AUTHORIZED_JIT_ACCESS_GRANTED')

        # 3. Verify single-use replay prevention (Replay attack must fail)
        replay_allowed, replay_receipt = self.delegator.authorize_and_consume(token, 'dynamodb:read')
        self.assertFalse(replay_allowed)
        self.assertEqual(replay_receipt.status, 'REJECTED_TOKEN_ALREADY_CONSUMED')

    def test_scope_escalation_quarantine(self):
        token = self.delegator.mint_ephemeral_token(
            agent_id='agent_readonly',
            allowed_scope='s3:GetObject',
        )
        # Rogue agent attempts privilege escalation to delete bucket
        allowed, receipt = self.delegator.authorize_and_consume(token, 's3:DeleteBucket')
        self.assertFalse(allowed)
        self.assertEqual(receipt.status, 'REJECTED_EXPIRED_OR_SCOPE_MISMATCH')

    def test_token_expiration_timeout(self):
        # Token with 1 second TTL
        token = self.delegator.mint_ephemeral_token(
            agent_id='agent_timeout_test',
            allowed_scope='k8s:list',
            ttl_seconds=1,
        )
        time.sleep(1.1)
        allowed, receipt = self.delegator.authorize_and_consume(token, 'k8s:list')
        self.assertFalse(allowed)
        self.assertEqual(receipt.status, 'REJECTED_EXPIRED_OR_SCOPE_MISMATCH')

    def test_ledger_integrity(self):
        is_valid, err = self.delegator.ledger.verify_chain_integrity()
        self.assertTrue(is_valid, f'IAM ledger broken: {err}')


if __name__ == '__main__':
    unittest.main()
