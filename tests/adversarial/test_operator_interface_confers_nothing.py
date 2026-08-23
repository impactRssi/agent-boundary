"""A payload-seeded ledger, read through the operator interface, grants nothing (N-45).

**Attack** A3 (confused deputy) and A9 (approval fatigue). **Carrier** every
carrier in the corpus. The payload does not have to be new, because the attack
is not on the broker: it is on the human who reads the refusals afterwards, and
on the interface that shows them.

The chain: content steers the agent toward a secret, the broker refuses, the
refusal lands in the ledger, and an operator later runs ``agent-boundary
refusals``. What that operator sees is a screen full of subjects an attacker
chose. The whole of node N-45 rests on that screen having no handle -- no row
number, no identifier -- and on ``lease grant`` having no way to consume one.

``tests/unit/test_operator_cli.py`` asserts the absence structurally. This file
asserts it against the real corpus, end to end, because a structural test passes
just as well when the corpus stops producing refusals at all.

**Invariant** I1 and I4, indirectly: neither may become conditional on a record
of having been enforced. **Expected refusal reason** the payload's own,
unchanged by anything the interface printed.
"""

from __future__ import annotations

import io
import json
from pathlib import Path

import pytest

from agentboundary.ledger import MemoryRefusalLedger, record_refusal
from agentboundary.model import Outcome
from agentboundary.operator.cli import build_parser, main
from agentboundary.testing import Payload, broker_for, load_corpus

pytestmark = pytest.mark.security

CORPUS_DIR = Path(__file__).resolve().parents[2] / "corpus" / "payloads"
PAYLOADS = load_corpus(CORPUS_DIR)


def _seeded_ledger(payload: Payload, root: Path, ledger_path: Path) -> str:
    """Drive the real broker, record the real refusal, write the ledger's own format."""
    broker = broker_for(payload, fs_root=str(root))
    decision = broker.authorise(payload.call)
    assert decision.outcome is Outcome.REFUSE, payload.id

    memory = MemoryRefusalLedger(clock=lambda: 1_700_000_000.0)
    event = record_refusal(memory, broker.task, payload.call, decision)
    assert event is not None
    with ledger_path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(event.to_json(), sort_keys=True) + "\n")
    return event.subject.value


@pytest.mark.parametrize("payload", PAYLOADS, ids=lambda payload: str(payload.id))
def test_the_attacker_chosen_subject_is_shown_with_its_caveat(
    payload: Payload, tmp_path: Path
) -> None:
    """The row is displayed -- an operator has to be able to triage -- and the
    sentence saying it is not a request is displayed with it, every time."""
    root = tmp_path / "workspace"
    root.mkdir()
    ledger = tmp_path / "refusals.jsonl"
    subject = _seeded_ledger(payload, root, ledger)

    stream = io.StringIO()
    assert main(["refusals", "--ledger", str(ledger)], stream, 1_700_000_000.0) == 0

    printed = stream.getvalue()
    assert subject in printed, payload.id
    assert "cannot distinguish a legitimate workflow from a payload" in printed


@pytest.mark.parametrize("payload", PAYLOADS, ids=lambda payload: str(payload.id))
def test_reading_the_ledger_writes_no_lease(payload: Payload, tmp_path: Path) -> None:
    """The command that reads refusals cannot create the file that grants."""
    root = tmp_path / "workspace"
    root.mkdir()
    ledger = tmp_path / "refusals.jsonl"
    _seeded_ledger(payload, root, ledger)

    before = sorted(item.name for item in tmp_path.iterdir())
    main(["refusals", "--ledger", str(ledger)], io.StringIO(), 1_700_000_000.0)
    main(["refusals", "--ledger", str(ledger), "--json"], io.StringIO(), 1_700_000_000.0)

    assert sorted(item.name for item in tmp_path.iterdir()) == before


@pytest.mark.parametrize("payload", PAYLOADS, ids=lambda payload: str(payload.id))
def test_a_seeded_ledger_still_refuses_the_same_call_afterwards(
    payload: Payload, tmp_path: Path
) -> None:
    """A fresh broker, built after the ledger exists and was read, decides the same.

    Repetition is not evidence of need, and neither is having been printed.
    """
    root = tmp_path / "workspace"
    root.mkdir()
    ledger = tmp_path / "refusals.jsonl"
    for _ in range(5):
        _seeded_ledger(payload, root, ledger)
    main(["refusals", "--ledger", str(ledger)], io.StringIO(), 1_700_000_000.0)

    decision = broker_for(payload, fs_root=str(root)).authorise(payload.call)
    assert decision.outcome is Outcome.REFUSE, (
        f"{payload.id} was authorised after its refusal was recorded five times and "
        f"shown to an operator. A ledger that widens under repetition is the "
        f"attacker's grant workflow."
    )
    assert str(decision.reason) == payload.expected_reason


class TestNoInvocationTurnsALedgerRowIntoALease:
    """There is no argv that names the ledger from the granting command."""

    @pytest.mark.parametrize(
        "argv",
        [
            ["lease", "grant", "--approve-all", "--store", "/tmp/s.jsonl"],
            ["lease", "grant", "--from-ledger", "/tmp/refusals.jsonl"],
            ["lease", "grant", "--ledger", "/tmp/refusals.jsonl"],
            ["lease", "grant", "--index", "0"],
            ["lease", "grant", "--subjects-from", "/tmp/refusals.jsonl"],
            ["lease", "grant", "--all"],
            ["lease", "grant", "--yes"],
            ["lease", "approve-all"],
        ],
    )
    def test_the_invocation_does_not_parse(self, argv: list[str]) -> None:
        with pytest.raises(SystemExit) as exit_info:
            build_parser().parse_args(argv)
        assert exit_info.value.code == 2

    def test_granting_the_subject_a_payload_produced_still_takes_a_typed_subject(
        self, tmp_path: Path
    ) -> None:
        """The escape hatch exists and costs the operator a decision each time.

        This is the honest half: the interface must be usable, or it is a denial
        rather than a control. What it must never be is usable in bulk.
        """
        store = tmp_path / "leases.jsonl"
        target = tmp_path / "secrets"
        target.mkdir()
        stream = io.StringIO()

        code = main(
            [
                "lease",
                "grant",
                "--store",
                str(store),
                "--kind",
                "path",
                "--subject",
                str(target),
                "--duration",
                "3d",
                "--granted-by",
                "operator@example.test",
                "--reason",
                "reviewed the refusals and this one is the nightly automation",
            ],
            stream,
            1_700_000_000.0,
        )

        assert code == 0
        assert len(store.read_text(encoding="utf-8").strip().split("\n")) == 1
