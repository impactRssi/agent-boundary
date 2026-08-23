"""The refusal ledger (N-41).

The tests are ordered the way the risk is: what the ledger must **not** do
first, then what it records, then how it renders.

The first class is the important one. A ledger that aggregates refusals is
useful; a ledger from which permission can be derived is an attacker-influenced
path into the allowlist (A3, A9). The control is an absence -- no approval
field, no grant method, no edge from this module to the lease module -- and an
absence has to be asserted by introspection, because nothing fails when someone
adds one.
"""

from __future__ import annotations

import inspect
import json
from pathlib import Path

import pytest

from agentboundary import ledger as ledger_module
from agentboundary.errors import RefusalReason
from agentboundary.ledger import (
    MAX_SAMPLE_TASK_IDS,
    FileRefusalLedger,
    LedgerEntry,
    MemoryRefusalLedger,
    RefusalEvent,
    RefusalLedger,
    RefusalSubject,
    StoreWithinReachError,
    SubjectKind,
    assert_out_of_reach,
    record_refusal,
    render,
    subject_for,
)
from agentboundary.model import Caps, Check, Decision, Outcome, ProposedCall, Task

CAPS = Caps(max_calls=10, max_cost=10.0, max_wall_clock_s=60.0)

#: Any of these appearing on a ledger type would mean a refusal can be turned
#: into permission from the record itself. Matched as substrings so that
#: `approve_all`, `bulk_grant` and `promote_to_lease` are all caught.
GRANTING_VOCABULARY = (
    "approve",
    "approval",
    "grant",
    "allow",
    "authorise",
    "authorize",
    "permit",
    "promote",
    "lease",
    "widen",
)


def _task(root: str | None = None, task_id: str = "t-1") -> Task:
    return Task(
        id=task_id,
        tool_scope=frozenset({"fs.read"}),
        fs_root=root,
        egress_allowlist=frozenset(),
        caps=CAPS,
    )


def _refusal(reason: RefusalReason, arguments: dict[str, object] | None = None) -> Decision:
    return Decision.refuse(reason, [Check(name="x", passed=False, detail="d")], arguments or {})


class TestTheLedgerConfersNothing:
    """The absence is the control. These tests are what makes it one."""

    def test_a_ledger_entry_has_no_field_that_could_carry_permission(self) -> None:
        fields = set(LedgerEntry.__dataclass_fields__)
        offending = {
            name for name in fields for word in GRANTING_VOCABULARY if word in name.lower()
        }
        assert not offending, (
            f"LedgerEntry gained field(s) {sorted(offending)}. A refusal record that "
            f"carries permission is the grant-from-the-ledger path this design refuses."
        )

    @pytest.mark.parametrize(
        "subject",
        [LedgerEntry, RefusalEvent, RefusalSubject, MemoryRefusalLedger, FileRefusalLedger],
        ids=lambda t: t.__name__,
    )
    def test_no_ledger_type_exposes_a_method_that_produces_permission(self, subject: type) -> None:
        offending = {
            name
            for name in dir(subject)
            if not name.startswith("_")
            for word in GRANTING_VOCABULARY
            if word in name.lower()
        }
        assert not offending, (
            f"{subject.__name__} exposes {sorted(offending)}. Granting must name its "
            f"subject explicitly, never derive it from a record of what was refused."
        )

    def test_the_ledger_protocol_offers_only_append_read_and_a_clock(self) -> None:
        """A wider protocol is a wider obligation on every implementation."""
        surface = {name for name in dir(RefusalLedger) if not name.startswith("_")}
        assert surface == {"record", "entries", "now"}

    def test_the_ledger_module_does_not_import_the_lease_module(self) -> None:
        """The dependency runs one way. An edge here is the trap re-opening."""
        source = Path(inspect.getsourcefile(ledger_module) or "").read_text(encoding="utf-8")
        assert "agentboundary.leases" not in source.replace("``agentboundary.leases``", "").replace(
            "from agentboundary.leases", "IMPORTED"
        ), (
            "agentboundary.ledger imports the lease module. A ledger that can see "
            "leases is one refactor away from producing one."
        )
        assert "from agentboundary.leases" not in source


class TestStoresMustBeOutOfTheAgentsReach:
    """An agent that can write its own ledger has no boundary at all."""

    def test_a_ledger_inside_the_task_root_is_refused_at_construction(self, tmp_path: Path) -> None:
        root = tmp_path / "workspace"
        root.mkdir()
        with pytest.raises(StoreWithinReachError, match="resolves inside fs_root"):
            assert_out_of_reach(root / "refusals.jsonl", str(root), "refusal ledger")

    def test_a_ledger_reached_through_a_symlink_into_the_root_is_refused(
        self, tmp_path: Path
    ) -> None:
        """Resolution first: a link is not a different location."""
        root = tmp_path / "workspace"
        root.mkdir()
        (root / "inner").mkdir()
        link = tmp_path / "link"
        link.symlink_to(root / "inner")
        with pytest.raises(StoreWithinReachError):
            assert_out_of_reach(link / "refusals.jsonl", str(root), "refusal ledger")

    def test_a_sibling_directory_sharing_a_prefix_is_not_inside_the_root(
        self, tmp_path: Path
    ) -> None:
        root = tmp_path / "workspace"
        root.mkdir()
        (tmp_path / "workspace-backup").mkdir()
        assert_out_of_reach(
            tmp_path / "workspace-backup" / "refusals.jsonl", str(root), "refusal ledger"
        )

    def test_an_unresolvable_root_refuses_rather_than_assuming_safety(self, tmp_path: Path) -> None:
        missing = tmp_path / "gone"
        with pytest.raises(StoreWithinReachError, match="refusing rather than assuming"):
            assert_out_of_reach(tmp_path / "refusals.jsonl", str(missing), "refusal ledger")

    def test_a_task_with_no_root_has_nothing_to_be_inside_of(self, tmp_path: Path) -> None:
        assert_out_of_reach(tmp_path / "refusals.jsonl", None, "refusal ledger")

    def test_a_relative_ledger_path_is_refused(self) -> None:
        with pytest.raises(ValueError, match="relative"):
            FileRefusalLedger("refusals.jsonl")


class TestSubjectNormalisation:
    """Two spellings of one subject must be one row, and near misses must not."""

    def test_a_path_refusal_records_the_resolved_location(self, tmp_path: Path) -> None:
        outside = tmp_path / "outside"
        outside.mkdir()
        root = tmp_path / "workspace"
        root.mkdir()
        subject = subject_for(
            _task(str(root)),
            ProposedCall("fs.read", {}),
            _refusal(RefusalReason.PATH_OUTSIDE_ROOT, {"path": "../outside/secret"}),
        )
        assert subject.kind is SubjectKind.PATH
        assert subject.resolved
        assert subject.value == str((outside / "secret").resolve())

    def test_two_spellings_of_one_path_aggregate_to_one_row(self, tmp_path: Path) -> None:
        root = tmp_path / "workspace"
        root.mkdir()
        (tmp_path / "outside").mkdir()
        task = _task(str(root))
        led = MemoryRefusalLedger(clock=lambda: 100.0)
        for spelling in ("../outside/secret", "./../outside/./secret"):
            record_refusal(
                led,
                task,
                ProposedCall("fs.read", {}),
                _refusal(RefusalReason.PATH_OUTSIDE_ROOT, {"path": spelling}),
            )
        assert len(led.entries()) == 1
        assert led.entries()[0].count == 2

    def test_a_sibling_path_is_a_separate_row(self, tmp_path: Path) -> None:
        root = tmp_path / "workspace"
        root.mkdir()
        (tmp_path / "secrets").mkdir()
        (tmp_path / "secrets-backup").mkdir()
        task = _task(str(root))
        led = MemoryRefusalLedger(clock=lambda: 1.0)
        for spelling in ("../secrets/prod.env", "../secrets-backup/prod.env"):
            record_refusal(
                led,
                task,
                ProposedCall("fs.read", {}),
                _refusal(RefusalReason.PATH_OUTSIDE_ROOT, {"path": spelling}),
            )
        assert len(led.entries()) == 2

    def test_an_unresolvable_path_is_recorded_as_the_literal_and_flagged(
        self, tmp_path: Path
    ) -> None:
        root = tmp_path / "workspace"
        root.mkdir()
        (root / "loop").symlink_to(root / "loop")
        subject = subject_for(
            _task(str(root)),
            ProposedCall("fs.read", {}),
            _refusal(RefusalReason.PATH_OUTSIDE_ROOT, {"path": "loop/secret"}),
        )
        assert subject.value == "loop/secret"
        assert not subject.resolved

    def test_a_path_refusal_with_no_root_records_the_literal(self) -> None:
        subject = subject_for(
            _task(None),
            ProposedCall("fs.read", {}),
            _refusal(RefusalReason.PATH_OUTSIDE_ROOT, {"path": "/etc/shadow"}),
        )
        assert subject.value == "/etc/shadow"
        assert not subject.resolved

    def test_a_host_refusal_records_the_normalised_host(self) -> None:
        subject = subject_for(
            _task(None),
            ProposedCall("http.get", {}),
            _refusal(
                RefusalReason.EGRESS_HOST_NOT_ALLOWED,
                {"url": "https://EVIL.example./steal?x=1"},
            ),
        )
        assert subject.kind is SubjectKind.HOST
        assert subject.value == "evil.example"

    def test_a_hostless_url_is_recorded_as_the_whole_argument(self) -> None:
        subject = subject_for(
            _task(None),
            ProposedCall("http.get", {}),
            _refusal(RefusalReason.EGRESS_HOST_NOT_ALLOWED, {"url": "file:///etc/passwd"}),
        )
        assert subject.kind is SubjectKind.HOST
        assert not subject.resolved

    @pytest.mark.parametrize(
        "reason",
        [
            RefusalReason.TOOL_NOT_IN_SCOPE,
            RefusalReason.SCHEMA_INVALID,
            RefusalReason.BUDGET_EXHAUSTED,
            RefusalReason.APPROVAL_REQUIRED,
            RefusalReason.APPROVAL_EXPIRED,
            RefusalReason.APPROVAL_MISMATCH,
            RefusalReason.TOOL_UNKNOWN,
            RefusalReason.TASK_CONSTRUCTION_FAILED,
        ],
        ids=str,
    )
    def test_every_other_reason_attributes_to_the_tool(self, reason: RefusalReason) -> None:
        """The mapping is total. An unattributable refusal is not triageable."""
        subject = subject_for(_task(None), ProposedCall("tickets.delete", {}), _refusal(reason))
        assert subject.kind is SubjectKind.TOOL
        assert subject.value == "tickets.delete"

    def test_a_path_refusal_with_no_path_argument_falls_back_to_the_tool(self) -> None:
        subject = subject_for(
            _task(None), ProposedCall("fs.read", {}), _refusal(RefusalReason.PATH_OUTSIDE_ROOT)
        )
        assert subject.kind is SubjectKind.TOOL

    def test_an_empty_subject_is_rejected(self) -> None:
        with pytest.raises(ValueError, match="cannot be empty"):
            RefusalSubject(kind=SubjectKind.TOOL, value="")


class TestRecording:
    def test_an_authorisation_is_not_recorded(self) -> None:
        led = MemoryRefusalLedger(clock=lambda: 0.0)
        authorised = Decision.authorise([Check(name="x", passed=True)], {}, cost=1.0)
        assert record_refusal(led, _task(), ProposedCall("fs.read", {}), authorised) is None
        assert led.entries() == ()

    def test_first_and_last_seen_come_from_the_injected_clock(self) -> None:
        ticks = iter([10.0, 20.0, 30.0])
        led = MemoryRefusalLedger(clock=lambda: next(ticks))
        for _ in range(3):
            record_refusal(
                led,
                _task(),
                ProposedCall("tickets.delete", {}),
                _refusal(RefusalReason.TOOL_NOT_IN_SCOPE),
            )
        entry = led.entries()[0]
        assert (entry.first_seen, entry.last_seen, entry.count) == (10.0, 30.0, 3)

    def test_task_ids_are_a_bounded_sample_not_a_census(self) -> None:
        led = MemoryRefusalLedger(clock=lambda: 0.0)
        for index in range(MAX_SAMPLE_TASK_IDS + 4):
            record_refusal(
                led,
                _task(task_id=f"t-{index}"),
                ProposedCall("tickets.delete", {}),
                _refusal(RefusalReason.TOOL_NOT_IN_SCOPE),
            )
        entry = led.entries()[0]
        assert len(entry.sample_task_ids) == MAX_SAMPLE_TASK_IDS
        assert entry.count == MAX_SAMPLE_TASK_IDS + 4

    def test_one_subject_refused_two_ways_is_two_rows(self) -> None:
        led = MemoryRefusalLedger(clock=lambda: 0.0)
        for reason in (RefusalReason.TOOL_NOT_IN_SCOPE, RefusalReason.APPROVAL_REQUIRED):
            record_refusal(led, _task(), ProposedCall("tickets.delete", {}), _refusal(reason))
        assert {entry.reason for entry in led.entries()} == {
            "tool_not_in_scope",
            "approval_required",
        }

    def test_entries_are_ordered_deterministically(self) -> None:
        led = MemoryRefusalLedger(clock=lambda: 0.0)
        for tool in ("zeta.tool", "alpha.tool", "mid.tool"):
            record_refusal(
                led, _task(), ProposedCall(tool, {}), _refusal(RefusalReason.TOOL_NOT_IN_SCOPE)
            )
        assert [entry.subject for entry in led.entries()] == [
            "alpha.tool",
            "mid.tool",
            "zeta.tool",
        ]


class TestTheFileLedgerIsAppendOnly:
    def test_events_are_appended_one_line_at_a_time(self, tmp_path: Path) -> None:
        led = FileRefusalLedger(tmp_path / "refusals.jsonl", clock=lambda: 5.0)
        for _ in range(2):
            record_refusal(
                led,
                _task(),
                ProposedCall("tickets.delete", {}),
                _refusal(RefusalReason.TOOL_NOT_IN_SCOPE),
            )
        lines = (tmp_path / "refusals.jsonl").read_text(encoding="utf-8").strip().split("\n")
        assert len(lines) == 2
        assert json.loads(lines[0])["reason"] == "tool_not_in_scope"

    def test_a_second_write_never_rewrites_the_first(self, tmp_path: Path) -> None:
        path = tmp_path / "refusals.jsonl"
        led = FileRefusalLedger(path, clock=lambda: 1.0)
        record_refusal(
            led, _task(), ProposedCall("a.tool", {}), _refusal(RefusalReason.TOOL_NOT_IN_SCOPE)
        )
        first = path.read_bytes()
        record_refusal(
            led, _task(), ProposedCall("b.tool", {}), _refusal(RefusalReason.TOOL_NOT_IN_SCOPE)
        )
        assert path.read_bytes().startswith(first)

    def test_the_file_is_not_world_readable(self, tmp_path: Path) -> None:
        path = tmp_path / "refusals.jsonl"
        led = FileRefusalLedger(path, clock=lambda: 1.0)
        record_refusal(
            led, _task(), ProposedCall("a.tool", {}), _refusal(RefusalReason.TOOL_NOT_IN_SCOPE)
        )
        assert path.stat().st_mode & 0o077 == 0

    def test_an_absent_file_reads_as_an_empty_ledger(self, tmp_path: Path) -> None:
        assert FileRefusalLedger(tmp_path / "none.jsonl").entries() == ()

    def test_blank_lines_are_ignored_on_read(self, tmp_path: Path) -> None:
        path = tmp_path / "refusals.jsonl"
        led = FileRefusalLedger(path, clock=lambda: 1.0)
        record_refusal(
            led, _task(), ProposedCall("a.tool", {}), _refusal(RefusalReason.TOOL_NOT_IN_SCOPE)
        )
        with path.open("a", encoding="utf-8") as handle:
            handle.write("\n\n")
        assert len(led.entries()) == 1

    def test_a_round_trip_preserves_the_subject(self, tmp_path: Path) -> None:
        path = tmp_path / "refusals.jsonl"
        led = FileRefusalLedger(path, clock=lambda: 7.0)
        record_refusal(
            led,
            _task(None),
            ProposedCall("http.get", {}),
            _refusal(RefusalReason.EGRESS_HOST_NOT_ALLOWED, {"url": "https://evil.example/x"}),
        )
        reread = FileRefusalLedger(path)
        assert reread.entries()[0].subject == "evil.example"
        assert reread.events()[0].at == 7.0


class TestRendering:
    def test_the_caveat_is_emitted_even_for_an_empty_ledger(self) -> None:
        text = render(())
        assert "not a request for permission" in text
        assert "No refusals recorded." in text

    def test_the_caveat_precedes_the_rows(self) -> None:
        led = MemoryRefusalLedger(clock=lambda: 0.0)
        record_refusal(
            led,
            _task(),
            ProposedCall("tickets.delete", {}),
            _refusal(RefusalReason.TOOL_NOT_IN_SCOPE),
        )
        text = render(led.entries())
        assert text.index("cannot distinguish a legitimate workflow") < text.index("tickets.delete")

    def test_an_unresolved_subject_is_marked_as_such_in_the_rendering(self) -> None:
        led = MemoryRefusalLedger(clock=lambda: 0.0)
        record_refusal(
            led,
            _task(None),
            ProposedCall("fs.read", {}),
            _refusal(RefusalReason.PATH_OUTSIDE_ROOT, {"path": "/etc/shadow"}),
        )
        assert "(unresolved)" in render(led.entries())

    def test_a_ledger_entry_serialises_to_a_stable_shape(self) -> None:
        entry = LedgerEntry(
            subject_kind="tool",
            subject="tickets.delete",
            resolved=True,
            reason="tool_not_in_scope",
            first_seen=1.0,
            last_seen=2.0,
            count=3,
            sample_task_ids=("t-1",),
        )
        assert set(entry.to_json()) == {
            "subject_kind",
            "subject",
            "resolved",
            "reason",
            "first_seen",
            "last_seen",
            "count",
            "sample_task_ids",
        }


class TestTheDecisionOutcomeIsNotSecondGuessed:
    def test_a_decision_carrying_no_reason_records_nothing(self) -> None:
        """Belt and braces: Decision forbids it, and this must not invent one."""
        led = MemoryRefusalLedger(clock=lambda: 0.0)
        authorised = Decision(outcome=Outcome.AUTHORISE, reason=None)
        assert record_refusal(led, _task(), ProposedCall("fs.read", {}), authorised) is None
