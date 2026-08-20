"""Append-only audit trace (N-09, I3). Refusals must be recorded too."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from agentboundary.audit import AuditRecord, FileAuditSink, MemoryAuditSink, ResultStatus
from agentboundary.errors import RefusalReason
from agentboundary.model import Caps, Check, Decision, ProposedCall, Task

CAPS = Caps(max_calls=5, max_cost=10.0, max_wall_clock_s=30.0)
TASK = Task(
    id="t-1",
    tool_scope=frozenset({"fs.read"}),
    fs_root=None,
    egress_allowlist=frozenset(),
    caps=CAPS,
)


def _refusal() -> AuditRecord:
    decision = Decision.refuse(
        RefusalReason.PATH_OUTSIDE_ROOT,
        [Check(name="scope", passed=True), Check(name="path", passed=False, detail="escaped")],
        {"path": "/etc/passwd"},
    )
    return AuditRecord.from_decision(
        TASK, ProposedCall("fs.read", {"path": "../etc/passwd"}), decision, sequence=1
    )


def _authorisation() -> AuditRecord:
    decision = Decision.authorise([Check(name="scope", passed=True)], {"path": "/srv/a"}, cost=1.0)
    return AuditRecord.from_decision(
        TASK, ProposedCall("fs.read", {"path": "/srv/a"}), decision, sequence=2
    )


class TestRefusalsAreRecorded:
    def test_a_refusal_produces_a_record(self) -> None:
        """FR-021. A trace holding only successes cannot answer 'what was attempted'."""
        record = _refusal()
        assert record.outcome == "refuse"
        assert record.reason == "path_outside_root"
        assert record.result_status == ResultStatus.REFUSED

    def test_the_record_carries_the_ordered_decision_path(self) -> None:
        record = _refusal()
        assert [c.name for c in record.checks] == ["scope", "path"]
        assert record.checks[-1].detail == "escaped"

    def test_a_refusal_records_zero_cost(self) -> None:
        assert _refusal().cost == 0.0


class TestAttribution:
    def test_the_record_holds_the_validated_arguments_not_the_proposal(self) -> None:
        """FR-008: the trace must show what the broker agreed to, not what was asked."""
        record = _refusal()
        assert record.validated_arguments == {"path": "/etc/passwd"}

    def test_the_proposed_tool_name_is_preserved(self) -> None:
        """An out-of-scope call has no resolved tool; the reached-for name is the artifact."""
        decision = Decision.refuse(RefusalReason.TOOL_NOT_IN_SCOPE, [])
        record = AuditRecord.from_decision(TASK, ProposedCall("tickets.delete"), decision, 1)
        assert record.tool_name == "tickets.delete"

    def test_the_task_id_is_present_on_every_record(self) -> None:
        assert _refusal().task_id == "t-1"
        assert _authorisation().task_id == "t-1"

    def test_an_authorised_call_starts_pending_not_succeeded(self) -> None:
        """Authorisation is not execution. Claiming success here would be a lie."""
        assert _authorisation().result_status == ResultStatus.AUTHORISED_PENDING


class TestMemorySink:
    def test_records_are_returned_in_order(self) -> None:
        sink = MemoryAuditSink()
        sink.append(_refusal())
        sink.append(_authorisation())
        assert [r.sequence for r in sink.records()] == [1, 2]

    def test_the_returned_trace_cannot_be_rewritten_through(self) -> None:
        """FR-022: a caller must not reach history through the value it was handed."""
        sink = MemoryAuditSink()
        sink.append(_refusal())
        returned = sink.records()
        assert isinstance(returned, tuple)
        with pytest.raises((AttributeError, TypeError)):
            returned[0] = _authorisation()  # type: ignore[index]

    def test_the_sink_exposes_no_mutation_operations(self) -> None:
        """The absence of the operation is the control, not a guard on it."""
        sink = MemoryAuditSink()
        for forbidden in ("update", "delete", "remove", "clear", "pop", "truncate"):
            assert not hasattr(sink, forbidden)


class TestFileSink:
    def test_records_round_trip_through_the_file(self, tmp_path: Path) -> None:
        sink = FileAuditSink(tmp_path / "trace.jsonl")
        sink.append(_refusal())
        sink.append(_authorisation())
        assert [r.sequence for r in sink.records()] == [1, 2]
        assert sink.records()[0].reason == "path_outside_root"

    def test_each_record_is_one_json_line(self, tmp_path: Path) -> None:
        path = tmp_path / "trace.jsonl"
        sink = FileAuditSink(path)
        sink.append(_refusal())
        sink.append(_authorisation())
        lines = path.read_text(encoding="utf-8").strip().split("\n")
        assert len(lines) == 2
        assert json.loads(lines[0])["reason"] == "path_outside_root"

    def test_appending_never_overwrites_earlier_records(self, tmp_path: Path) -> None:
        path = tmp_path / "trace.jsonl"
        FileAuditSink(path).append(_refusal())
        # A second sink over the same path, as a restarted process would create.
        FileAuditSink(path).append(_authorisation())
        assert len(FileAuditSink(path).records()) == 2

    def test_the_trace_is_not_world_readable(self, tmp_path: Path) -> None:
        """A trace carries validated arguments: paths, ids, sometimes more."""
        path = tmp_path / "trace.jsonl"
        FileAuditSink(path).append(_refusal())
        assert path.stat().st_mode & 0o077 == 0

    def test_the_parent_directory_is_created(self, tmp_path: Path) -> None:
        sink = FileAuditSink(tmp_path / "nested" / "deeper" / "trace.jsonl")
        sink.append(_refusal())
        assert sink.path.exists()

    def test_the_sink_exposes_no_mutation_operations(self, tmp_path: Path) -> None:
        sink = FileAuditSink(tmp_path / "trace.jsonl")
        for forbidden in ("update", "delete", "remove", "clear", "truncate", "rewrite"):
            assert not hasattr(sink, forbidden)

    def test_blank_lines_are_tolerated_on_read(self, tmp_path: Path) -> None:
        """A partially flushed line from a killed process must not break triage."""
        path = tmp_path / "trace.jsonl"
        FileAuditSink(path).append(_refusal())
        with path.open("a", encoding="utf-8") as handle:
            handle.write("\n")
        assert len(FileAuditSink(path).records()) == 1

    def test_the_descriptor_is_opened_append_only(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Append-only is a property of the descriptor, not a promise of the class.

        O_APPEND makes the kernel place every write at the current end of file,
        so a handle obtained this way cannot seek back over existing bytes.
        """
        sink = FileAuditSink(tmp_path / "trace.jsonl")
        flags_seen: list[int] = []
        real_open = os.open

        def spy(path: object, flags: int, mode: int = 0o777) -> int:
            flags_seen.append(flags)
            return real_open(path, flags, mode)  # type: ignore[arg-type]

        monkeypatch.setattr(os, "open", spy)
        sink.append(_refusal())

        assert flags_seen, "the sink did not open a descriptor"
        assert flags_seen[0] & os.O_APPEND
        assert not flags_seen[0] & os.O_TRUNC


class TestSerialisation:
    def test_the_json_shape_is_stable_and_sorted(self, tmp_path: Path) -> None:
        """A viewer and a human both read this; key order must not drift."""
        path = tmp_path / "trace.jsonl"
        FileAuditSink(path).append(_refusal())
        raw = path.read_text(encoding="utf-8").strip()
        assert raw == json.dumps(json.loads(raw), ensure_ascii=False, sort_keys=True)

    def test_every_documented_field_is_present(self) -> None:
        payload = _refusal().to_json()
        for field in (
            "sequence",
            "task_id",
            "tool_name",
            "outcome",
            "reason",
            "result_status",
            "cost",
            "validated_arguments",
            "checks",
        ):
            assert field in payload
