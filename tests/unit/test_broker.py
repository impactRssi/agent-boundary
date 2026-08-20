"""The decision pipeline (N-08). Order and determinism are the contract."""

from __future__ import annotations

import pytest

from agentboundary.broker import Broker
from agentboundary.errors import RefusalReason
from agentboundary.guards import CallContext, GuardResult
from agentboundary.model import Caps, Irreversibility, ProposedCall, Task, Tool
from agentboundary.registry import ToolRegistry

CAPS = Caps(max_calls=5, max_cost=10.0, max_wall_clock_s=30.0)
READ_SCHEMA = {
    "type": "object",
    "properties": {"path": {"type": "string", "minLength": 1}},
    "required": ["path"],
}


class RecordingGuard:
    """Test double that records whether it ran, and how it was asked."""

    def __init__(self, name: str, result: GuardResult) -> None:
        self._name = name
        self._result = result
        self.calls: list[CallContext] = []

    @property
    def name(self) -> str:
        return self._name

    def check(self, context: CallContext) -> GuardResult:
        self.calls.append(context)
        return self._result


class RaisingGuard:
    name = "explodes"

    def check(self, context: CallContext) -> GuardResult:
        del context
        msg = "guard is broken"
        raise RuntimeError(msg)


def _broker(*guards: object, scope: tuple[str, ...] = ("fs.read",)) -> Broker:
    registry = ToolRegistry(
        [
            Tool(
                name="fs.read",
                arg_schema=READ_SCHEMA,
                irreversibility=Irreversibility.READ,
                cost_weight=2.0,
            ),
            Tool(name="tickets.delete", arg_schema={}),
        ]
    )
    task = Task(
        id="t-1", tool_scope=frozenset(scope), fs_root=None, egress_allowlist=frozenset(), caps=CAPS
    )
    return Broker(task, registry.scope_for(task), list(guards))  # type: ignore[arg-type]


class TestScopeRefusal:
    def test_an_out_of_scope_tool_is_refused(self) -> None:
        decision = _broker().authorise(ProposedCall("tickets.delete", {}))
        assert not decision.authorised
        assert decision.reason is RefusalReason.TOOL_NOT_IN_SCOPE

    def test_the_scope_refusal_lists_what_was_in_scope(self) -> None:
        """An operator triaging must not have to reconstruct the task by hand."""
        decision = _broker().authorise(ProposedCall("tickets.delete", {}))
        assert "fs.read" in decision.checks[0].detail

    def test_a_zero_scope_task_refuses_everything(self) -> None:
        decision = _broker(scope=()).authorise(ProposedCall("fs.read", {"path": "/a"}))
        assert decision.reason is RefusalReason.TOOL_NOT_IN_SCOPE

    def test_no_guard_runs_when_the_tool_is_out_of_scope(self) -> None:
        """Scope refusal precedes everything. Nothing downstream is reachable."""
        guard = RecordingGuard("later", GuardResult.ok())
        _broker(guard).authorise(ProposedCall("tickets.delete", {}))
        assert guard.calls == []


class TestSchemaRefusal:
    def test_invalid_arguments_are_refused(self) -> None:
        decision = _broker().authorise(ProposedCall("fs.read", {}))
        assert decision.reason is RefusalReason.SCHEMA_INVALID

    def test_a_malformed_schema_fails_closed(self) -> None:
        """A tool whose schema cannot be evaluated must not be callable."""
        registry = ToolRegistry([Tool(name="bad", arg_schema={"oneOf": []})])
        task = Task(
            id="t",
            tool_scope=frozenset({"bad"}),
            fs_root=None,
            egress_allowlist=frozenset(),
            caps=CAPS,
        )
        decision = Broker(task, registry.scope_for(task)).authorise(ProposedCall("bad", {}))
        assert decision.reason is RefusalReason.SCHEMA_INVALID
        assert "malformed schema" in decision.checks[-1].detail

    def test_no_guard_runs_when_validation_fails(self) -> None:
        """FR-007: a malformed call cannot reach budget accounting."""
        guard = RecordingGuard("budget", GuardResult.ok())
        _broker(guard).authorise(ProposedCall("fs.read", {"path": 42}))
        assert guard.calls == []

    def test_a_refused_call_costs_nothing(self) -> None:
        assert _broker().authorise(ProposedCall("fs.read", {})).cost == 0.0


class TestGuardOrdering:
    def test_guards_run_in_registration_order(self) -> None:
        order: list[str] = []

        class Ordered(RecordingGuard):
            def check(self, context: CallContext) -> GuardResult:
                order.append(self.name)
                return super().check(context)

        first = Ordered("first", GuardResult.ok())
        second = Ordered("second", GuardResult.ok())
        _broker(first, second).authorise(ProposedCall("fs.read", {"path": "/a"}))
        assert order == ["first", "second"]

    def test_a_failing_guard_short_circuits_the_rest(self) -> None:
        blocker = RecordingGuard(
            "blocker", GuardResult.refuse(RefusalReason.BUDGET_EXHAUSTED, "cap reached")
        )
        downstream = RecordingGuard("downstream", GuardResult.ok())
        decision = _broker(blocker, downstream).authorise(ProposedCall("fs.read", {"path": "/a"}))
        assert decision.reason is RefusalReason.BUDGET_EXHAUSTED
        assert downstream.calls == []

    def test_every_guard_that_ran_is_recorded(self) -> None:
        passing = RecordingGuard("passing", GuardResult.ok("fine"))
        failing = RecordingGuard(
            "failing", GuardResult.refuse(RefusalReason.PATH_OUTSIDE_ROOT, "escaped")
        )
        decision = _broker(passing, failing).authorise(ProposedCall("fs.read", {"path": "/a"}))
        names = [check.name for check in decision.checks]
        assert names == ["scope", "schema", "passing", "failing"]
        assert decision.checks[-1].detail == "escaped"


class TestGuardsSeeOnlyValidatedArguments:
    def test_guards_receive_the_validated_form(self) -> None:
        """FR-008. A confinement check on a raw argument checks a value we never agreed to."""
        guard = RecordingGuard("inspect", GuardResult.ok())
        _broker(guard).authorise(ProposedCall("fs.read", {"path": "/srv/a"}))
        assert guard.calls[0].validated_arguments == {"path": "/srv/a"}

    def test_a_guard_cannot_reach_the_agent_context(self) -> None:
        """FR-023 as a missing field: there is nothing to consult."""
        guard = RecordingGuard("inspect", GuardResult.ok())
        _broker(guard).authorise(ProposedCall("fs.read", {"path": "/srv/a"}))
        context = guard.calls[0]
        assert not hasattr(context, "messages")
        assert not hasattr(context, "conversation")
        assert not hasattr(context, "system_prompt")


class TestBrokenGuardFailsClosed:
    def test_a_guard_that_raises_produces_a_refusal_not_an_authorisation(self) -> None:
        """Treating an undecided guard as a pass would make every guard bug an opening."""
        decision = _broker(RaisingGuard()).authorise(ProposedCall("fs.read", {"path": "/a"}))
        assert not decision.authorised
        assert decision.reason is RefusalReason.TASK_CONSTRUCTION_FAILED
        assert "RuntimeError" in decision.checks[-1].detail


class TestAuthorisation:
    def test_an_in_scope_valid_call_is_authorised(self) -> None:
        decision = _broker().authorise(ProposedCall("fs.read", {"path": "/srv/a"}))
        assert decision.authorised
        assert decision.reason is None
        assert decision.validated_arguments == {"path": "/srv/a"}

    def test_the_authorised_cost_is_the_tool_weight(self) -> None:
        assert _broker().authorise(ProposedCall("fs.read", {"path": "/a"})).cost == 2.0


class TestDeterminism:
    def test_identical_inputs_produce_an_identical_decision(self) -> None:
        """NFR-002. Same task, same call, same verdict, same reason, same path."""
        call = ProposedCall("fs.read", {"path": "/srv/a"})
        first = _broker().authorise(call)
        second = _broker().authorise(call)
        assert first == second

    def test_identical_refusals_are_identical(self) -> None:
        call = ProposedCall("tickets.delete", {})
        assert _broker().authorise(call) == _broker().authorise(call)


class TestPipelineIsFixedAtConstruction:
    def test_mutating_the_guard_sequence_afterwards_does_not_reach_the_broker(self) -> None:
        guards: list[object] = []
        broker = Broker(
            Task(
                id="t",
                tool_scope=frozenset(),
                fs_root=None,
                egress_allowlist=frozenset(),
                caps=CAPS,
            ),
            ToolRegistry().scope_for(
                Task(
                    id="t",
                    tool_scope=frozenset(),
                    fs_root=None,
                    egress_allowlist=frozenset(),
                    caps=CAPS,
                )
            ),
            guards,  # type: ignore[arg-type]
        )
        guards.append(RecordingGuard("late", GuardResult.ok()))
        assert broker.guard_names == ()


class TestGuardResultInvariants:
    def test_a_failing_result_without_a_reason_is_unrepresentable(self) -> None:
        with pytest.raises(ValueError, match="must name a refusal reason"):
            GuardResult(passed=False, reason=None)

    def test_a_passing_result_carrying_a_reason_is_rejected(self) -> None:
        with pytest.raises(ValueError, match="cannot name a refusal reason"):
            GuardResult(passed=True, reason=RefusalReason.BUDGET_EXHAUSTED)
