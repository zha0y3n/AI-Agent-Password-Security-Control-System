"""Agent and Authorization Authority reference implementation."""

from .authority import AuthorizationAuthority
from .models import (
    AgentRequest,
    CapabilityBody,
    ExecutionReceipt,
    HolderProof,
    SignedCapability,
    SignedReceipt,
    TaskContext,
)

__all__ = [
    "AgentRequest",
    "AuthorizationAuthority",
    "CapabilityBody",
    "ExecutionReceipt",
    "HolderProof",
    "SignedCapability",
    "SignedReceipt",
    "TaskContext",
]

__version__ = "0.1.0"
