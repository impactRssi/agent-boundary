"""The guard protocol -- the extension point of the decision pipeline.

A guard answers one question about one proposed call and returns a verdict. It
is ordinary, deterministic code: no model, no heuristic, no network, no clock
it did not receive (FR-024, ADR-0001).

Guards are ordered and every one that runs is recorded, passed or failed, so
the audit trace shows the reasoning rather than only the conclusion (FR-021).
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable

from agentboundary.errors import RefusalReason
from agentboundary.model import ProposedCall, Task, Tool

__all__ = ["CallContext", "Guard", "GuardResult"]


@dataclass(frozen=True, slots=True)
class CallContext:
    """Everything a guard is allowed to see.

    Note what is absent: the agent's context, the conversation, the model's
    stated intent. A guard cannot consult them because they are not reachable
    from here -- FR-023 expressed as a missing field rather than as a rule.
    """

    task: Task
    tool: Tool
    proposed: ProposedCall
    validated_arguments: Mapping[str, Any]


@dataclass(frozen=True, slots=True)
class GuardResult:
    """A guard's verdict. A refusal must name a reason from the closed set."""

    passed: bool
    reason: RefusalReason | None = None
    detail: str = ""

    def __post_init__(self) -> None:
        if not self.passed and self.reason is None:
            msg = "a failing guard must name a refusal reason from the closed set"
            raise ValueError(msg)
        if self.passed and self.reason is not None:
            msg = "a passing guard cannot name a refusal reason"
            raise ValueError(msg)

    @classmethod
    def ok(cls, detail: str = "") -> GuardResult:
        return cls(passed=True, detail=detail)

    @classmethod
    def refuse(cls, reason: RefusalReason, detail: str = "") -> GuardResult:
        return cls(passed=False, reason=reason, detail=detail)


@runtime_checkable
class Guard(Protocol):
    """One deterministic check on the authorisation path."""

    @property
    def name(self) -> str:
        """Stable identifier recorded in the audit trace."""
        ...

    def check(self, context: CallContext) -> GuardResult:
        """Decide. Must not perform I/O with side effects, and must not block."""
        ...
