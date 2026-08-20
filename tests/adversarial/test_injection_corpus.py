"""The indirect-injection corpus (N-17).

Every payload asserts a **refusal**, and asserts the specific refusal reason.
A test that only checked "no effect happened" would also pass if the broker
crashed, if the tool silently did nothing, or if the harness never ran the
call -- and those are exactly the shapes a broken control takes.

Each payload runs against the **complete** guard pipeline. Disabling the guards
a given payload does not target would prove each control works in isolation,
which is not the claim.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from agentboundary.model import Outcome
from agentboundary.testing import Payload, broker_for, load_corpus

CORPUS_DIR = Path(__file__).resolve().parents[2] / "corpus" / "payloads"
PAYLOADS = load_corpus(CORPUS_DIR)

#: Floors from SPEC.md TR-002 and TR-003. Asserted rather than assumed: a
#: corpus that quietly shrinks below them stops being the evidence the README
#: claims it is.
REQUIRED_PAYLOADS = 30
REQUIRED_CARRIERS = 7
ATTACK_TABLE = ("A1", "A2", "A3", "A4", "A5", "A6", "A7", "A8", "A9")


@pytest.mark.parametrize("payload", PAYLOADS, ids=lambda payload: str(payload.id))
def test_the_broker_refuses_the_resulting_call(payload: Payload, tmp_path: Path) -> None:
    """The attack was attempted against the full pipeline and was refused."""
    root = tmp_path / "workspace"
    root.mkdir()
    broker = broker_for(payload, fs_root=str(root))

    decision = broker.authorise(payload.call)

    assert decision.outcome is Outcome.REFUSE, (
        f"{payload.id} ({payload.attack} via {payload.carrier}) was AUTHORISED. "
        f"{payload.description}"
    )
    assert decision.reason is not None
    assert str(decision.reason) == payload.expected_reason, (
        f"{payload.id} was refused for {decision.reason!s}, but the payload "
        f"targets {payload.invariant} and expects {payload.expected_reason}. "
        f"A refusal for the wrong reason means the control that fired is not "
        f"the control being tested."
    )


@pytest.mark.parametrize("payload", PAYLOADS, ids=lambda payload: str(payload.id))
def test_a_refused_call_costs_no_budget(payload: Payload, tmp_path: Path) -> None:
    """A refusal that still debited budget would let refusals exhaust a task."""
    root = tmp_path / "workspace"
    root.mkdir()
    decision = broker_for(payload, fs_root=str(root)).authorise(payload.call)
    assert decision.cost == 0.0


@pytest.mark.parametrize("payload", PAYLOADS, ids=lambda payload: str(payload.id))
def test_the_refusal_is_attributable(payload: Payload, tmp_path: Path) -> None:
    """An effect that cannot be traced to a decision is a finding (I3)."""
    root = tmp_path / "workspace"
    root.mkdir()
    decision = broker_for(payload, fs_root=str(root)).authorise(payload.call)
    assert decision.checks, f"{payload.id} produced no decision path"
    assert not decision.checks[-1].passed
    assert decision.checks[-1].detail, f"{payload.id} refused without a stated detail"


class TestCorpusCoverage:
    """The corpus must keep meeting the floors the README relies on."""

    def test_the_corpus_meets_the_payload_floor(self) -> None:
        assert len(PAYLOADS) >= REQUIRED_PAYLOADS

    def test_the_corpus_meets_the_carrier_floor(self) -> None:
        carriers = {payload.carrier for payload in PAYLOADS}
        assert len(carriers) >= REQUIRED_CARRIERS, sorted(carriers)

    def test_every_attack_table_row_has_a_payload(self) -> None:
        """TR-002. A row with no payload is a claim with no evidence."""
        covered = {payload.attack for payload in PAYLOADS}
        missing = sorted(set(ATTACK_TABLE) - covered)
        assert not missing, f"attack table rows with no payload: {missing}"

    def test_every_payload_expects_a_reason_the_broker_can_produce(self) -> None:
        """A typo in expected_reason would make a payload unfalsifiable."""
        from agentboundary.errors import RefusalReason

        known = {reason.value for reason in RefusalReason}
        for payload in PAYLOADS:
            assert payload.expected_reason in known, payload.id
