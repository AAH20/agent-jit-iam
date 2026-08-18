"""
Agent-JIT-IAM: Ephemeral Just-In-Time IAM Token & Zero-Standing-Privilege Delegator.
"""

from agentiam.core import (
    AgentJITDelegator,
    CryptographicIAMLedger,
    EphemeralJITToken,
    IAMReceipt,
    GENESIS_HASH,
)

__all__ = [
    "AgentJITDelegator",
    "CryptographicIAMLedger",
    "EphemeralJITToken",
    "IAMReceipt",
    "GENESIS_HASH",
]

__version__ = "1.0.0"
