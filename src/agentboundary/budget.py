"""Per-task budget accounting -- invariant I3, FR-012 and FR-013.

Three caps, because an agent can be made to burn resources along three
different axes and bounding one leaves the others open: call count, cumulative
cost, and wall-clock. A slow endpoint polled in a loop costs almost nothing per
call and still denies service.

At any cap the task **fails closed** and says so. It does not fall back to a
cheaper tool, does not silently stop, and does not finish the turn quietly.
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from dataclasses import dataclass

from agentboundary.errors import RefusalReason
from agentboundary.guards import CallContext, GuardResult
from agentboundary.model import Caps

__all__ = ["BudgetGuard", "BudgetLedger", "BudgetState"]


@dataclass(frozen=True, slots=True)
class BudgetState:
    """What a task has consumed. Snapshot, not a live view."""

    calls: int
    cost: float
    elapsed_s: float
    exhausted: bool
    reason: str = ""


class BudgetLedger:
    """Tracks consumption for one task and decides when it is spent.

    The clock is injected. A ledger that reads the wall clock directly cannot
    be tested deterministically, and NFR-002 requires the decision path to be
    reproducible -- including the path that refuses.

    Once exhausted, a ledger stays exhausted. Recovery would mean a task that
    hit its cap could resume, which is not what failing closed means.
    """

    __slots__ = ("_calls", "_caps", "_clock", "_cost", "_lock", "_reason", "_started")

    def __init__(self, caps: Caps, clock: Callable[[], float] | None = None) -> None:
        if clock is None:
            import time

            clock = time.monotonic
        self._caps = caps
        self._clock = clock
        self._calls = 0
        self._cost = 0.0
        self._reason = ""
        self._lock = threading.Lock()
        self._started = clock()

    @property
    def caps(self) -> Caps:
        return self._caps

    def state(self) -> BudgetState:
        with self._lock:
            return self._snapshot()

    def _snapshot(self) -> BudgetState:
        elapsed = self._clock() - self._started
        exhausted = bool(self._reason) or self._is_over(self._calls, self._cost, elapsed)
        reason = self._reason or self._describe(self._calls, self._cost, elapsed)
        return BudgetState(
            calls=self._calls,
            cost=self._cost,
            elapsed_s=elapsed,
            exhausted=exhausted,
            reason=reason if exhausted else "",
        )

    def _is_over(self, calls: int, cost: float, elapsed: float) -> bool:
        return (
            calls >= self._caps.max_calls
            or cost >= self._caps.max_cost
            or elapsed >= self._caps.max_wall_clock_s
        )

    def _describe(self, calls: int, cost: float, elapsed: float) -> str:
        if calls >= self._caps.max_calls:
            return f"call cap reached: {calls}/{self._caps.max_calls}"
        if cost >= self._caps.max_cost:
            return f"cost cap reached: {cost:.4f}/{self._caps.max_cost}"
        if elapsed >= self._caps.max_wall_clock_s:
            return f"wall-clock cap reached: {elapsed:.3f}s/{self._caps.max_wall_clock_s}s"
        return ""

    def would_exceed(self, cost: float) -> str:
        """Return a refusal description if admitting ``cost`` would breach a cap.

        Checked **before** the call is admitted, not after. Detecting an
        overrun once the effect has happened is accounting, not a control.
        """
        with self._lock:
            elapsed = self._clock() - self._started
            if self._reason:
                return self._reason
            projected_calls = self._calls + 1
            projected_cost = self._cost + cost
            if projected_calls > self._caps.max_calls:
                return f"call cap would be exceeded: {projected_calls}/{self._caps.max_calls}"
            if projected_cost > self._caps.max_cost:
                return f"cost cap would be exceeded: {projected_cost:.4f}/{self._caps.max_cost}"
            if elapsed >= self._caps.max_wall_clock_s:
                return f"wall-clock cap reached: {elapsed:.3f}s/{self._caps.max_wall_clock_s}s"
            return ""

    def debit(self, cost: float) -> BudgetState:
        """Record an admitted call.

        Called only after the broker authorises, so a refused call debits
        nothing (FR-007). Latching ``_reason`` here is what makes exhaustion
        terminal: the next :meth:`would_exceed` returns the same description
        rather than re-deriving a possibly different one.
        """
        if cost < 0:
            msg = "cost cannot be negative; a refund would let a task loop forever"
            raise ValueError(msg)
        with self._lock:
            self._calls += 1
            self._cost += cost
            elapsed = self._clock() - self._started
            if not self._reason and self._is_over(self._calls, self._cost, elapsed):
                self._reason = self._describe(self._calls, self._cost, elapsed)
            return self._snapshot()


class BudgetGuard:
    """Refuses a call that would breach any cap (I3, FR-012, FR-013)."""

    __slots__ = ("_ledger",)

    def __init__(self, ledger: BudgetLedger) -> None:
        self._ledger = ledger

    @property
    def name(self) -> str:
        return "budget"

    @property
    def ledger(self) -> BudgetLedger:
        return self._ledger

    def check(self, context: CallContext) -> GuardResult:
        breach = self._ledger.would_exceed(context.tool.cost_weight)
        if breach:
            return GuardResult.refuse(
                RefusalReason.BUDGET_EXHAUSTED,
                f"{breach}. Task {context.task.id!r} fails closed.",
            )
        state = self._ledger.state()
        return GuardResult.ok(
            f"within caps: {state.calls}/{self._ledger.caps.max_calls} calls, "
            f"{state.cost:.4f}/{self._ledger.caps.max_cost} cost"
        )
