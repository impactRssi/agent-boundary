"""A payload-driven refusal is recorded, and the record grants nothing (N-41).

**Attack** A3 (confused deputy) and A9 (approval fatigue), in the shape the
ledger itself creates. **Carrier** every carrier in the corpus -- the payload
does not have to be new for the attack to be new, because the attack is on what
happens *after* the refusal.

The chain being tested: a payload steers the agent toward a subject, the broker
refuses, the refusal is written down, and the written-down refusal is later read
as a list of things the agent needed. This suite asserts that the third step
produces evidence and the fourth step has no mechanism.

**Invariant** I1 and I4, indirectly: neither may become conditional on a record
of having been enforced. **Expected refusal reason** the payload's own, before
and after the ledger has seen it.
"""

from __future__ import annotations

import inspect
from pathlib import Path

import pytest

from agentboundary.broker import Broker
from agentboundary.guards import CallContext
from agentboundary.ledger import (
    MemoryRefusalLedger,
    record_refusal,
    render,
)
from agentboundary.model import Outcome
from agentboundary.testing import Payload, broker_for, load_corpus

CORPUS_DIR = Path(__file__).resolve().parents[2] / "corpus" / "payloads"
PAYLOADS = load_corpus(CORPUS_DIR)


@pytest.mark.parametrize("payload", PAYLOADS, ids=lambda payload: str(payload.id))
def test_the_refusal_is_recorded_with_a_subject_and_a_reason(
    payload: Payload, tmp_path: Path
) -> None:
    """A refusal an operator cannot attribute to a subject is not triageable."""
    root = tmp_path / "workspace"
    root.mkdir()
    broker = broker_for(payload, fs_root=str(root))
    decision = broker.authorise(payload.call)
    assert decision.outcome is Outcome.REFUSE, payload.id

    led = MemoryRefusalLedger(clock=lambda: 1_000.0)
    event = record_refusal(led, broker.task, payload.call, decision)

    assert event is not None, f"{payload.id} was refused but produced no ledger event"
    assert event.reason == payload.expected_reason
    assert event.subject.value, f"{payload.id} recorded an empty subject"
    entries = led.entries()
    assert len(entries) == 1
    assert entries[0].count == 1
    assert entries[0].sample_task_ids == (broker.task.id,)


@pytest.mark.parametrize("payload", PAYLOADS, ids=lambda payload: str(payload.id))
def test_a_recorded_refusal_does_not_widen_the_next_decision(
    payload: Payload, tmp_path: Path
) -> None:
    """Repetition is not evidence of need. Ten refusals authorise nothing.

    This is the attack the ledger would otherwise enable: content that induces
    a retry loop produces a high count, and a high count reads as a legitimate
    requirement. The count must move the number and nothing else.
    """
    root = tmp_path / "workspace"
    root.mkdir()
    broker = broker_for(payload, fs_root=str(root))
    led = MemoryRefusalLedger(clock=lambda: 1.0)

    for _ in range(10):
        decision = broker.authorise(payload.call)
        record_refusal(led, broker.task, payload.call, decision)

    assert led.entries()[0].count == 10
    final = broker.authorise(payload.call)
    assert final.outcome is Outcome.REFUSE, (
        f"{payload.id} was authorised after being refused ten times. "
        f"A refusal ledger that widens under repetition is an attacker's grant workflow."
    )
    assert str(final.reason) == payload.expected_reason


@pytest.mark.parametrize("payload", PAYLOADS, ids=lambda payload: str(payload.id))
def test_a_ledger_built_from_one_payload_authorises_none_of_it(
    payload: Payload, tmp_path: Path
) -> None:
    """A fresh broker knows nothing of the ledger, and the ledger cannot tell it."""
    root = tmp_path / "workspace"
    root.mkdir()
    seeded = MemoryRefusalLedger(clock=lambda: 1.0)
    first = broker_for(payload, fs_root=str(root))
    record_refusal(seeded, first.task, payload.call, first.authorise(payload.call))
    assert seeded.entries()

    # A second broker, assembled exactly as the first, with the ledger in
    # existence and no way to hand it over. That impossibility is the control.
    second = broker_for(payload, fs_root=str(root))
    decision = second.authorise(payload.call)
    assert decision.outcome is Outcome.REFUSE
    assert str(decision.reason) == payload.expected_reason


class TestTheAuthorisationPathCannotSeeTheLedger:
    """Structural, not behavioural: there is no parameter to pass it through."""

    def test_the_broker_takes_no_ledger(self) -> None:
        parameters = set(inspect.signature(Broker.__init__).parameters)
        assert parameters == {"self", "task", "scoped", "guards"}, (
            "Broker.__init__ gained a parameter. If it is a refusal ledger, the "
            "authorisation path can now read what it previously refused."
        )

    def test_a_guard_cannot_see_a_ledger(self) -> None:
        assert set(CallContext.__dataclass_fields__) == {
            "task",
            "tool",
            "proposed",
            "validated_arguments",
        }

    def test_the_rendered_ledger_states_what_it_cannot_tell_a_reviewer(
        self, tmp_path: Path
    ) -> None:
        """The caveat travels with the rows, or an operator reads a to-do list."""
        root = tmp_path / "workspace"
        root.mkdir()
        led = MemoryRefusalLedger(clock=lambda: 1.0)
        for payload in PAYLOADS[:5]:
            broker = broker_for(payload, fs_root=str(root))
            record_refusal(led, broker.task, payload.call, broker.authorise(payload.call))
        text = render(led.entries())
        assert "cannot distinguish a legitimate workflow from a payload" in text
        assert "Nothing here grants anything." in text
