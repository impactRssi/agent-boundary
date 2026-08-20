"""Domain model for the authorisation path.

Every type here is frozen. A ``Task`` constructed before the agent loop starts
cannot be widened once the loop is running -- that is invariant I1 expressed in
the type system rather than in a convention someone has to remember (FR-001).
"""

from __future__ import annotations

import unicodedata
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from agentboundary.errors import RefusalReason

__all__ = [
    "Caps",
    "Check",
    "Decision",
    "Irreversibility",
    "Outcome",
    "ProposedCall",
    "Task",
    "Tool",
    "normalise_tool_name",
]


def normalise_tool_name(name: str) -> str:
    """Canonicalise a tool name for exact matching.

    NFKC folding collapses the confusable and compatibility forms an attacker
    would otherwise use to smuggle a near-miss name past scope resolution. What
    it deliberately does **not** do is make matching tolerant: after folding,
    comparison is exact. A name that is merely *similar* to an in-scope tool
    does not resolve to it (FR-005).
    """
    return unicodedata.normalize("NFKC", name).strip()


class Irreversibility(str, Enum):
    """How hard it is to undo a tool's effect.

    The ordering matters: ``IRREVERSIBLE`` is the default for an unclassified
    tool (FR-014), because the unsafe default is the one we refuse to make
    convenient. See ADR-0004.
    """

    READ = "read"
    REVERSIBLE = "reversible"
    IRREVERSIBLE = "irreversible"

    def __str__(self) -> str:
        return self.value


class Outcome(str, Enum):
    """The broker's verdict on a proposed call."""

    AUTHORISE = "authorise"
    REFUSE = "refuse"

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True, slots=True)
class Caps:
    """Per-task hard limits (I3, FR-012).

    Wall-clock is included alongside count and cost because an agent can burn a
    budget in ways that are cheap per call: a slow endpoint polled in a loop
    costs little and still denies service.
    """

    max_calls: int
    max_cost: float
    max_wall_clock_s: float

    def __post_init__(self) -> None:
        if self.max_calls < 0:
            msg = "max_calls cannot be negative"
            raise ValueError(msg)
        if self.max_cost < 0:
            msg = "max_cost cannot be negative"
            raise ValueError(msg)
        if self.max_wall_clock_s <= 0:
            msg = "max_wall_clock_s must be positive"
            raise ValueError(msg)


@dataclass(frozen=True, slots=True)
class Tool:
    """A capability the broker can authorise.

    ``arg_schema`` is the subset of JSON Schema supported by
    ``agentboundary.schema``. ``cost_weight`` is what a single call debits from
    ``Caps.max_cost``.
    """

    name: str
    arg_schema: Mapping[str, Any]
    irreversibility: Irreversibility = Irreversibility.IRREVERSIBLE
    cost_weight: float = 1.0
    description: str = ""

    def __post_init__(self) -> None:
        if not self.name.strip():
            msg = "tool name cannot be empty"
            raise ValueError(msg)
        if self.cost_weight < 0:
            msg = f"tool {self.name!r}: cost_weight cannot be negative"
            raise ValueError(msg)
        # Names are stored already normalised so that every comparison
        # downstream is a plain equality check on a canonical form.
        object.__setattr__(self, "name", normalise_tool_name(self.name))


@dataclass(frozen=True, slots=True)
class Task:
    """The unit of scoping. Immutable once constructed (I1).

    Everything the broker consults lives here. Nothing it consults lives in the
    agent's context -- that separation is the whole design (FR-023, ADR-0001).
    """

    id: str
    tool_scope: frozenset[str]
    fs_root: str | None
    egress_allowlist: frozenset[str]
    caps: Caps

    def __post_init__(self) -> None:
        if not self.id.strip():
            msg = "task id cannot be empty"
            raise ValueError(msg)

    def is_in_scope(self, tool_name: str) -> bool:
        """Exact match on the normalised name. No fuzzy resolution (FR-005)."""
        return normalise_tool_name(tool_name) in self.tool_scope


@dataclass(frozen=True, slots=True)
class ProposedCall:
    """What the agent emitted. Untrusted in full -- name and arguments alike."""

    tool_name: str
    arguments: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class Check:
    """One step of the decision pipeline, recorded whether it passed or not.

    The ordered list of checks is what lets an operator reconstruct *why* a
    call was authorised, not merely *that* it was (FR-021).
    """

    name: str
    passed: bool
    detail: str = ""


@dataclass(frozen=True, slots=True)
class Decision:
    """The broker's output: a verdict, a reason, and the path that produced it."""

    outcome: Outcome
    reason: RefusalReason | None = None
    checks: tuple[Check, ...] = ()
    validated_arguments: Mapping[str, Any] = field(default_factory=dict)
    cost: float = 0.0

    def __post_init__(self) -> None:
        if self.outcome is Outcome.REFUSE and self.reason is None:
            msg = "a refusal must carry a reason; an unexplained refusal is not triageable"
            raise ValueError(msg)
        if self.outcome is Outcome.AUTHORISE and self.reason is not None:
            msg = "an authorisation cannot carry a refusal reason"
            raise ValueError(msg)

    @property
    def authorised(self) -> bool:
        return self.outcome is Outcome.AUTHORISE

    @classmethod
    def authorise(
        cls,
        checks: Sequence[Check],
        validated_arguments: Mapping[str, Any],
        cost: float,
    ) -> Decision:
        return cls(
            outcome=Outcome.AUTHORISE,
            reason=None,
            checks=tuple(checks),
            validated_arguments=dict(validated_arguments),
            cost=cost,
        )

    @classmethod
    def refuse(
        cls,
        reason: RefusalReason,
        checks: Sequence[Check],
        validated_arguments: Mapping[str, Any] | None = None,
    ) -> Decision:
        return cls(
            outcome=Outcome.REFUSE,
            reason=reason,
            checks=tuple(checks),
            validated_arguments=dict(validated_arguments or {}),
            cost=0.0,
        )
