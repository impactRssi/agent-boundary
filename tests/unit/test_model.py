"""Domain model (N-05). The types must make illegal states unrepresentable."""

from __future__ import annotations

import pytest

from agentboundary.errors import RefusalReason
from agentboundary.model import (
    Caps,
    Check,
    Decision,
    Irreversibility,
    Outcome,
    ProposedCall,
    Task,
    Tool,
    normalise_tool_name,
)


def _caps() -> Caps:
    return Caps(max_calls=5, max_cost=1.0, max_wall_clock_s=30.0)


class TestToolNameNormalisation:
    """Folding must collapse evasion forms without making matching tolerant."""

    def test_compatibility_forms_fold_to_the_same_name(self) -> None:
        # U+FF46 FULLWIDTH LATIN SMALL LETTER F -- a classic near-miss carrier.
        assert normalise_tool_name("\uff46s.read") == "fs.read"

    def test_surrounding_whitespace_is_stripped(self) -> None:
        assert normalise_tool_name("  fs.read \n") == "fs.read"

    def test_a_merely_similar_name_does_not_collapse(self) -> None:
        """Folding is not fuzzy matching. Near-misses must stay distinct."""
        assert normalise_tool_name("fs_read") != normalise_tool_name("fs.read")
        assert normalise_tool_name("fs.readx") != normalise_tool_name("fs.read")


class TestCaps:
    def test_negative_call_cap_is_rejected(self) -> None:
        with pytest.raises(ValueError, match="max_calls cannot be negative"):
            Caps(max_calls=-1, max_cost=1.0, max_wall_clock_s=1.0)

    def test_negative_cost_cap_is_rejected(self) -> None:
        with pytest.raises(ValueError, match="max_cost cannot be negative"):
            Caps(max_calls=1, max_cost=-0.01, max_wall_clock_s=1.0)

    def test_zero_wall_clock_is_rejected(self) -> None:
        """A zero deadline would refuse every call and read as a broker bug."""
        with pytest.raises(ValueError, match="max_wall_clock_s must be positive"):
            Caps(max_calls=1, max_cost=1.0, max_wall_clock_s=0.0)

    def test_a_zero_call_cap_is_legal(self) -> None:
        """Legal, and every call under it refuses. Useful for a dry run."""
        assert Caps(max_calls=0, max_cost=0.0, max_wall_clock_s=1.0).max_calls == 0


class TestTool:
    def test_unclassified_tool_defaults_to_irreversible(self) -> None:
        """FR-014: the unsafe default is the one we refuse to make convenient."""
        assert Tool(name="x", arg_schema={}).irreversibility is Irreversibility.IRREVERSIBLE

    def test_empty_name_is_rejected(self) -> None:
        with pytest.raises(ValueError, match="cannot be empty"):
            Tool(name="   ", arg_schema={})

    def test_negative_cost_weight_is_rejected(self) -> None:
        """A negative weight would let a call refund budget and loop forever."""
        with pytest.raises(ValueError, match="cost_weight cannot be negative"):
            Tool(name="x", arg_schema={}, cost_weight=-1.0)

    def test_name_is_stored_normalised(self) -> None:
        assert Tool(name="\uff46s.read", arg_schema={}).name == "fs.read"

    def test_tool_is_immutable(self) -> None:
        tool = Tool(name="x", arg_schema={})
        with pytest.raises((AttributeError, TypeError)):
            tool.irreversibility = Irreversibility.READ  # type: ignore[misc]


class TestTask:
    def test_empty_id_is_rejected(self) -> None:
        with pytest.raises(ValueError, match="task id cannot be empty"):
            Task(
                id="",
                tool_scope=frozenset(),
                fs_root=None,
                egress_allowlist=frozenset(),
                caps=_caps(),
            )

    def test_scope_membership_is_exact_after_normalisation(self) -> None:
        task = Task(
            id="t",
            tool_scope=frozenset({"fs.read"}),
            fs_root=None,
            egress_allowlist=frozenset(),
            caps=_caps(),
        )
        assert task.is_in_scope("fs.read")
        assert task.is_in_scope("\uff46s.read")
        assert not task.is_in_scope("fs.write")
        assert not task.is_in_scope("fs.rea")

    def test_zero_tool_scope_is_legal(self) -> None:
        """FR-004. Nothing is in scope, so every call refuses."""
        task = Task(
            id="t", tool_scope=frozenset(), fs_root=None, egress_allowlist=frozenset(), caps=_caps()
        )
        assert not task.is_in_scope("anything")

    def test_task_is_immutable(self) -> None:
        """I1 in the type system: scope cannot widen once the loop is running."""
        task = Task(
            id="t", tool_scope=frozenset(), fs_root=None, egress_allowlist=frozenset(), caps=_caps()
        )
        with pytest.raises((AttributeError, TypeError)):
            task.tool_scope = frozenset({"fs.read"})  # type: ignore[misc]


class TestDecision:
    def test_a_refusal_without_a_reason_is_unrepresentable(self) -> None:
        """An unexplained refusal cannot be triaged, so it cannot be built."""
        with pytest.raises(ValueError, match="must carry a reason"):
            Decision(outcome=Outcome.REFUSE, reason=None)

    def test_an_authorisation_carrying_a_refusal_reason_is_rejected(self) -> None:
        with pytest.raises(ValueError, match="cannot carry a refusal reason"):
            Decision(outcome=Outcome.AUTHORISE, reason=RefusalReason.BUDGET_EXHAUSTED)

    def test_refuse_constructor_records_the_checks_that_ran(self) -> None:
        decision = Decision.refuse(
            RefusalReason.TOOL_NOT_IN_SCOPE,
            [Check(name="scope", passed=False, detail="fs.read not in scope")],
        )
        assert not decision.authorised
        assert decision.reason is RefusalReason.TOOL_NOT_IN_SCOPE
        assert decision.checks[0].passed is False
        assert decision.cost == 0.0

    def test_a_refused_call_never_costs_budget(self) -> None:
        """FR-007: validation precedes accounting, so a refusal debits nothing."""
        assert Decision.refuse(RefusalReason.SCHEMA_INVALID, []).cost == 0.0

    def test_authorise_carries_validated_arguments_and_cost(self) -> None:
        decision = Decision.authorise(
            [Check(name="scope", passed=True)], {"path": "/srv/data/a.txt"}, cost=1.5
        )
        assert decision.authorised
        assert decision.reason is None
        assert decision.validated_arguments == {"path": "/srv/data/a.txt"}
        assert decision.cost == 1.5


class TestProposedCall:
    def test_arguments_default_to_empty(self) -> None:
        assert ProposedCall(tool_name="fs.read").arguments == {}


class TestRefusalReasonWireFormat:
    def test_reason_serialises_as_its_stable_string(self) -> None:
        """The audit trace and the wire carry the string, not an ordinal."""
        assert str(RefusalReason.PATH_OUTSIDE_ROOT) == "path_outside_root"
        assert RefusalReason.PATH_OUTSIDE_ROOT.value == "path_outside_root"
        # Round-trips from the wire form, so a stored trace stays readable.
        assert RefusalReason("path_outside_root") is RefusalReason.PATH_OUTSIDE_ROOT
