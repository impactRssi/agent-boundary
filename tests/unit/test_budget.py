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
        """A slow endpoint polled in a loop costs little and still denies service."""
        clock = FakeClock()
        ledger = BudgetLedger(_caps(calls=1000, cost=1000.0, wall=10.0), clock=clock)
        context = _context(_caps(calls=1000, cost=1000.0, wall=10.0))
        assert BudgetGuard(ledger).check(context).passed
        clock.advance(10.0)
        result = BudgetGuard(ledger).check(context)
        assert not result.passed
        assert "wall-clock" in result.detail


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
