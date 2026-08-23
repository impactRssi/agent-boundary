"""Agent Boundary -- a deterministic tool-call broker for LLM agents.

The broker decides which proposed tool calls become effects. It is
deterministic and model-free: its inputs are the task construction, fixed
before the agent loop starts, and the proposed call. It never reads the
model's context.

Start at :class:`agentboundary.broker.Broker`, or at
:func:`agentboundary.mcp.server.build_server` to put it behind a process
boundary -- which is the supported way to use it, because a broker imported as
a library is one import away from being bypassed.

Nothing here is a claim about model alignment. The design assumes the model is
hostile; see ``docs/THREAT_MODEL.md``.
"""

from agentboundary.broker import Broker
from agentboundary.errors import BrokerError, RefusalReason, TaskConstructionError
from agentboundary.guards import CallContext, Guard, GuardResult
from agentboundary.ledger import (
    FileRefusalLedger,
    LedgerEntry,
    MemoryRefusalLedger,
    RefusalEvent,
    RefusalLedger,
    RefusalSubject,
    StoreWithinReachError,
    SubjectKind,
)
from agentboundary.model import (
    Caps,
    Check,
    Decision,
    Irreversibility,
    Outcome,
    ProposedCall,
    Task,
    Tool,
)
from agentboundary.registry import ScopedTools, ToolRegistry

__all__ = [
    "Broker",
    "BrokerError",
    "CallContext",
    "Caps",
    "Check",
    "Decision",
    "FileRefusalLedger",
    "Guard",
    "GuardResult",
    "Irreversibility",
    "LedgerEntry",
    "MemoryRefusalLedger",
    "Outcome",
    "ProposedCall",
    "RefusalEvent",
    "RefusalLedger",
    "RefusalReason",
    "RefusalSubject",
    "ScopedTools",
    "StoreWithinReachError",
    "SubjectKind",
    "Task",
    "TaskConstructionError",
    "Tool",
    "ToolRegistry",
    "__version__",
]

__version__ = "0.2.3"
