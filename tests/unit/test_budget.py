"""Budget accounting and fail-closed behaviour (N-12, I3)."""

from __future__ import annotations

import pytest

from agentboundary.budget import BudgetGuard, BudgetLedger
from agentboundary.errors import RefusalReason
from agentboundary.guards import CallContext
from agentboundary.model import Caps, ProposedCall, Task, Tool


class FakeClock:
    """Injected so the refusal path is reproducible, not only the success path."""

    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def _caps(calls: int = 3, cost: float = 10.0, wall: float = 60.0) -> Caps:
    return Caps(max_calls=calls, max_cost=cost, max_wall_clock_s=wall)


def _context(ledger_caps: Caps, weight: float = 1.0) -> CallContext:
    tool = Tool(name="http.get", arg_schema={}, cost_weight=weight)
    task = Task(
        id="t-1",
        tool_scope=frozenset({tool.name}),
        fs_root=None,
        egress_allowlist=frozenset(),
        caps=ledger_caps,
    )
    return CallContext(
        task=task, tool=tool, proposed=ProposedCall(tool.name), validated_arguments={}
    )


class TestCallCap:
    def test_the_call_after_the_cap_is_refused(self) -> None:
        clock = FakeClock()
        ledger = BudgetLedger(_caps(calls=2), clock=clock)
        guard = BudgetGuard(ledger)
        context = _context(_caps(calls=2))

        for _ in range(2):
            assert guard.check(context).passed
            ledger.debit(context.tool.cost_weight)

        result = guard.check(context)
        assert not result.passed
        assert result.reason is RefusalReason.BUDGET_EXHAUSTED
        assert "fails closed" in result.detail

    def test_a_zero_call_cap_refuses_the_first_call(self) -> None:
        ledger = BudgetLedger(_caps(calls=0), clock=FakeClock())
        assert not BudgetGuard(ledger).check(_context(_caps(calls=0))).passed


class TestCostCap:
    def test_a_call_that_would_breach_the_cost_cap_is_refused_before_it_runs(self) -> None:
        """Detecting an overrun after the effect is accounting, not a control."""
        ledger = BudgetLedger(_caps(calls=100, cost=1.0), clock=FakeClock())
        context = _context(_caps(calls=100, cost=1.0), weight=0.75)
        assert BudgetGuard(ledger).check(context).passed
        ledger.debit(0.75)
        result = BudgetGuard(ledger).check(context)
        assert not result.passed
        assert "cost cap" in result.detail


class TestWallClockCap:
    def test_a_task_past_its_deadline_is_refused_even_below_other_caps(self) -> None:
        """Polling a slow endpoint costs little per call and still denies service."""
        clock = FakeClock()
        ledger = BudgetLedger(_caps(calls=1000, cost=1000.0, wall=10.0), clock=clock)
        context = _context(_caps(calls=1000, cost=1000.0, wall=10.0))
        assert BudgetGuard(ledger).check(context).passed
        clock.advance(10.0)
        result = BudgetGuard(ledger).check(context)
        assert not result.passed
        assert "wall-clock" in result.detail


class TestWallClockMeasuresTheTaskSpan:
    """What the cap counts, pinned so a later refactor cannot quietly change it.

    The span runs from ledger construction, not from the first call and not as
    a sum of call durations. That is what bounds how long a steered agent may
    keep acting -- and it is also why an interactive task, where most of the
    span is model latency and human reading time, needs a larger number than a
    batch one. An operator who sizes this cap as though it measured time spent
    inside calls will size it far too small.
    """

    def test_the_cap_binds_with_no_call_ever_admitted(self) -> None:
        clock = FakeClock()
        caps = _caps(calls=1000, cost=1000.0, wall=10.0)
        ledger = BudgetLedger(caps, clock=clock)

        clock.advance(10.0)

        state = ledger.state()
        assert state.calls == 0, "nothing was admitted, so nothing should be counted"
        assert state.cost == 0.0
        assert state.exhausted, "idle time alone spends the span"
        assert "wall-clock" in state.reason

    def test_idle_time_between_calls_is_charged_to_the_span(self) -> None:
        clock = FakeClock()
        caps = _caps(calls=1000, cost=1000.0, wall=100.0)
        ledger = BudgetLedger(caps, clock=clock)

        clock.advance(30.0)  # waiting on the model, not on a tool
        ledger.debit(1.0)
        clock.advance(5.0)

        state = ledger.state()
        assert state.elapsed_s == pytest.approx(35.0)
        assert state.calls == 1
        assert not state.exhausted

    def test_the_span_is_not_the_sum_of_call_durations(self) -> None:
        """Twenty instant calls spread over an hour exhaust an hour-long cap."""
        clock = FakeClock()
        caps = _caps(calls=1000, cost=1000.0, wall=3600.0)
        ledger = BudgetLedger(caps, clock=clock)
        context = _context(caps)

        for _ in range(20):
            assert BudgetGuard(ledger).check(context).passed
            ledger.debit(0.0)  # the call itself takes no measurable time
            clock.advance(180.0)  # three minutes of model latency between turns

        result = BudgetGuard(ledger).check(context)
        assert not result.passed
        assert "wall-clock" in result.detail
        assert ledger.state().cost == 0.0, "the span bound it, not the cost"


class TestExhaustionIsTerminal:
    def test_an_exhausted_ledger_does_not_recover(self) -> None:
        """Failing closed means the task is over, not paused."""
        clock = FakeClock()
        ledger = BudgetLedger(_caps(calls=1000, cost=1000.0, wall=5.0), clock=clock)
        context = _context(_caps(calls=1000, cost=1000.0, wall=5.0))
        clock.advance(5.0)
        assert not BudgetGuard(ledger).check(context).passed
        ledger.debit(1.0)
        # Even if time were to somehow move back, the latch holds.
        clock.now = 0.0
        assert not BudgetGuard(ledger).check(context).passed

    def test_the_state_reports_exhaustion_explicitly(self) -> None:
        """FR-013: the task reports the state rather than stopping quietly."""
        ledger = BudgetLedger(_caps(calls=1), clock=FakeClock())
        ledger.debit(1.0)
        state = ledger.state()
        assert state.exhausted
        assert "call cap reached" in state.reason


class TestAccounting:
    def test_a_refused_call_debits_nothing(self) -> None:
        ledger = BudgetLedger(_caps(calls=1), clock=FakeClock())
        BudgetGuard(ledger).check(_context(_caps(calls=1)))
        assert ledger.state().calls == 0
        assert ledger.state().cost == 0.0

    def test_a_negative_cost_is_rejected(self) -> None:
        """A refund would let an induced loop run forever."""
        ledger = BudgetLedger(_caps(), clock=FakeClock())
        with pytest.raises(ValueError, match="cannot be negative"):
            ledger.debit(-1.0)

    def test_debiting_accumulates(self) -> None:
        ledger = BudgetLedger(_caps(calls=10, cost=10.0), clock=FakeClock())
        ledger.debit(1.5)
        ledger.debit(2.5)
        assert ledger.state().calls == 2
        assert ledger.state().cost == 4.0

    def test_the_passing_detail_reports_remaining_headroom(self) -> None:
        ledger = BudgetLedger(_caps(calls=3), clock=FakeClock())
        detail = BudgetGuard(ledger).check(_context(_caps(calls=3))).detail
        assert "0/3 calls" in detail


class TestCommitIsPartOfThePipeline:
    """Regression: nothing debited the ledger in the assembled system.

    The unit tests debited by hand, so the cap appeared to work. End to end no
    transport ever called debit, the ledger stayed empty, and the cap never
    bound. Making commit a pipeline step is what closes that, so it is asserted
    here rather than only through the E2E tier.
    """

    def test_the_guard_exposes_a_commit_hook(self) -> None:
        from agentboundary.guards import CommittingGuard

        guard = BudgetGuard(BudgetLedger(_caps(), clock=FakeClock()))
        assert isinstance(guard, CommittingGuard)

    def test_committing_debits_the_ledger(self) -> None:
        ledger = BudgetLedger(_caps(calls=5), clock=FakeClock())
        guard = BudgetGuard(ledger)
        guard.commit(_context(_caps(calls=5), weight=2.0))
        assert ledger.state().calls == 1
        assert ledger.state().cost == 2.0

    def test_the_broker_debits_only_on_a_full_authorisation(self) -> None:
        """A call refused by a later guard must cost nothing (FR-007)."""
        from agentboundary.broker import Broker
        from agentboundary.errors import RefusalReason
        from agentboundary.guards import GuardResult
        from agentboundary.model import Task
        from agentboundary.registry import ToolRegistry

        caps = _caps(calls=5)
        ledger = BudgetLedger(caps, clock=FakeClock())

        class AlwaysRefuse:
            name = "downstream"

            def check(self, context: object) -> GuardResult:
                del context
                return GuardResult.refuse(RefusalReason.APPROVAL_REQUIRED, "no")

        tool = Tool(name="http.get", arg_schema={}, cost_weight=1.0)
        task = Task(
            id="t",
            tool_scope=frozenset({tool.name}),
            fs_root=None,
            egress_allowlist=frozenset(),
            caps=caps,
        )
        registry = ToolRegistry([tool])
        broker = Broker(task, registry.scope_for(task), [BudgetGuard(ledger), AlwaysRefuse()])

        decision = broker.authorise(ProposedCall("http.get", {}))
        assert not decision.authorised
        assert ledger.state().calls == 0

    def test_the_broker_debits_when_the_pipeline_authorises(self) -> None:
        from agentboundary.broker import Broker
        from agentboundary.model import Task
        from agentboundary.registry import ToolRegistry

        caps = _caps(calls=5)
        ledger = BudgetLedger(caps, clock=FakeClock())
        tool = Tool(name="http.get", arg_schema={}, cost_weight=1.5)
        task = Task(
            id="t",
            tool_scope=frozenset({tool.name}),
            fs_root=None,
            egress_allowlist=frozenset(),
            caps=caps,
        )
        registry = ToolRegistry([tool])
        broker = Broker(task, registry.scope_for(task), [BudgetGuard(ledger)])

        assert broker.authorise(ProposedCall("http.get", {})).authorised
        assert ledger.state().calls == 1
        assert ledger.state().cost == 1.5
