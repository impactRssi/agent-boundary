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
from agentboundary.confinement import StoreWithinReachError
from agentboundary.errors import BrokerError, RefusalReason, TaskConstructionError
from agentboundary.guards import CallContext, Guard, GuardResult
from agentboundary.leases import (
    FileLeaseStore,
    InMemoryLeaseStore,
    Lease,
    LeaseError,
    LeaseKind,
    LeaseStore,
    Sensitivity,
    leased_task,
)
from agentboundary.ledger import (
    FileRefusalLedger,
    LedgerEntry,
    MemoryRefusalLedger,
    RefusalEvent,
    RefusalLedger,
    RefusalSubject,
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
from agentboundary.rotation import (
    AdvisorySink,
    FileAdvisorySink,
    MemoryAdvisorySink,
    RotationAdvice,
)

__all__ = [
    "AdvisorySink",
    "Broker",
    "BrokerError",
    "CallContext",
    "Caps",
    "Check",
    "Decision",
    "FileAdvisorySink",
    "FileLeaseStore",
    "FileRefusalLedger",
    "Guard",
    "GuardResult",
    "InMemoryLeaseStore",
    "Irreversibility",
    "Lease",
    "LeaseError",
    "LeaseKind",
    "LeaseStore",
    "LedgerEntry",
    "MemoryAdvisorySink",
    "MemoryRefusalLedger",
    "Outcome",
    "ProposedCall",
    "RefusalEvent",
    "RefusalLedger",
    "RefusalReason",
    "RefusalSubject",
    "RotationAdvice",
    "ScopedTools",
    "Sensitivity",
    "StoreWithinReachError",
    "SubjectKind",
    "Task",
    "TaskConstructionError",
    "Tool",
    "ToolRegistry",
    "__version__",
    "leased_task",
]

__version__ = "0.4.0"
