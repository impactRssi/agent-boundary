"""The broker -- the only thing in this system that can authorise an effect.

Deterministic and model-free. Its inputs are the task construction, fixed
before the loop started, and the proposed call. It reads no conversation, no
system prompt, and no tool output; a claim in context that approval was granted
is inert here because there is no code path by which it arrives (FR-023,
FR-024, ADR-0001).

Order is part of the contract:

1. **Resolve the tool in the task's scope.** An out-of-scope name refuses here,
   before any handler is reachable (I1).
2. **Validate the arguments.** Everything after this consumes the *validated*
   form, never the raw proposal (FR-008).
3. **Run the registered guards in order**, recording each.

Validation precedes every guard so that a malformed call cannot consume budget
(FR-007). A refused call costs nothing.
"""

from __future__ import annotations

from collections.abc import Sequence

from agentboundary.errors import RefusalReason
from agentboundary.guards import CallContext, CommittingGuard, Guard, GuardResult
from agentboundary.model import Check, Decision, ProposedCall, Task
from agentboundary.registry import ScopedTools
from agentboundary.schema import SchemaError, ValidationError, validate

__all__ = ["Broker"]

_SCOPE_CHECK = "scope"
_SCHEMA_CHECK = "schema"


class Broker:
    """Authorises or refuses one proposed call at a time, for one task."""

    __slots__ = ("_guards", "_scoped", "_task")

    def __init__(self, task: Task, scoped: ScopedTools, guards: Sequence[Guard] = ()) -> None:
        self._task = task
        self._scoped = scoped
        # Copied, and ordered. A guard list that could be appended to while the
        # loop runs would let the pipeline change shape mid-task; a tuple says
        # the pipeline is fixed at construction, like the scope it enforces.
        self._guards: tuple[Guard, ...] = tuple(guards)

    @property
    def task(self) -> Task:
        return self._task

    @property
    def scoped_tools(self) -> ScopedTools:
        return self._scoped

    @property
    def guard_names(self) -> tuple[str, ...]:
        return tuple(guard.name for guard in self._guards)

    def authorise(self, proposed: ProposedCall) -> Decision:
        """Decide on one proposed call.

        Never raises for an ordinary refusal: a refusal is a normal outcome
        carried in the :class:`Decision`, and the caller must be able to record
        it without an exception handler that could swallow it.
        """
        checks: list[Check] = []

        tool = self._scoped.get(proposed.tool_name)
        if tool is None:
            checks.append(
                Check(
                    name=_SCOPE_CHECK,
                    passed=False,
                    detail=(
                        f"{proposed.tool_name!r} is not in scope for task "
                        f"{self._task.id!r}; in scope: "
                        f"{', '.join(sorted(self._scoped.names())) or '(none)'}"
                    ),
                )
            )
            return Decision.refuse(RefusalReason.TOOL_NOT_IN_SCOPE, checks)
        checks.append(Check(name=_SCOPE_CHECK, passed=True, detail=tool.name))

        try:
            validated = validate(proposed.arguments, tool.arg_schema)
        except ValidationError as exc:
            checks.append(Check(name=_SCHEMA_CHECK, passed=False, detail=str(exc)))
            return Decision.refuse(RefusalReason.SCHEMA_INVALID, checks)
        except SchemaError as exc:
            # The schema itself is malformed -- a deployment defect, not hostile
            # input. Still refused, and fail closed: a tool whose schema cannot
            # be evaluated must not be callable on an unvalidated argument.
            checks.append(
                Check(
                    name=_SCHEMA_CHECK,
                    passed=False,
                    detail=f"malformed schema for {tool.name!r}: {exc}",
                )
            )
            return Decision.refuse(RefusalReason.SCHEMA_INVALID, checks)
        checks.append(Check(name=_SCHEMA_CHECK, passed=True))

        context = CallContext(
            task=self._task,
            tool=tool,
            proposed=proposed,
            validated_arguments=validated,
        )

        for guard in self._guards:
            result = self._run_guard(guard, context)
            checks.append(Check(name=guard.name, passed=result.passed, detail=result.detail))
            if not result.passed:
                # `reason` is non-None by GuardResult's own invariant.
                assert result.reason is not None  # noqa: S101
                return Decision.refuse(result.reason, checks, validated)

        # Every guard that keeps state is told, and only now: a call refused
        # by a later guard must cost nothing (FR-007). Doing this here rather
        # than in each transport is what stops a caller from silently omitting
        # it -- which would leave budget consulted but never accumulated, so
        # the cap would never bind.
        for guard in self._guards:
            if isinstance(guard, CommittingGuard):
                guard.commit(context)

        return Decision.authorise(checks, validated, cost=tool.cost_weight)

    @staticmethod
    def _run_guard(guard: Guard, context: CallContext) -> GuardResult:
        """Run a guard, converting an unexpected failure into a refusal.

        A guard that raises has not decided. Treating that as authorisation
        would make every bug in a guard an opening; treating it as a refusal
        fails closed, which is the standing rule when a precondition cannot be
        verified.
        """
        try:
            return guard.check(context)
        except Exception as exc:  # Deliberate catch-all: an undecided guard must refuse, not pass.
            return GuardResult.refuse(
                RefusalReason.TASK_CONSTRUCTION_FAILED,
                f"guard {guard.name!r} raised {type(exc).__name__}: {exc}. "
                f"A guard that cannot decide refuses.",
            )
