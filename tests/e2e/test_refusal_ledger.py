"""End-to-end: refusals reach an on-disk ledger the agent cannot reach (N-41)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agentboundary.ledger import (
    FileRefusalLedger,
    StoreWithinReachError,
    render,
)
from agentboundary.mcp.server import build_broker, build_server
from agentboundary.model import Caps, Task
from agentboundary.testing.catalogue import reference_registry
from tests.e2e.conftest import ServerFactory

pytestmark = pytest.mark.e2e


class TestRefusalsReachTheLedger:
    def test_a_confinement_refusal_is_recorded_with_the_resolved_subject(
        self, make_server: ServerFactory, workspace: Path, tmp_path: Path
    ) -> None:
        """The file was not read, and the attempt is attributable to a location."""
        outside = workspace.parent / "secrets.txt"
        led = FileRefusalLedger(tmp_path / "out-of-reach" / "refusals.jsonl", clock=lambda: 42.0)
        server = make_server({"fs.read"}, refusals=led)

        outcome = server.call_tool("fs.read", {"path": "../secrets.txt"})

        assert not outcome.authorised
        assert outcome.refusal_reason == "path_outside_root"
        entries = led.entries()
        assert len(entries) == 1
        assert entries[0].subject == str(outside.resolve())
        assert entries[0].reason == "path_outside_root"
        assert entries[0].sample_task_ids == ("e2e-task",)

    def test_an_out_of_scope_call_is_recorded_against_the_tool(
        self, make_server: ServerFactory, tmp_path: Path
    ) -> None:
        led = FileRefusalLedger(tmp_path / "ledger.jsonl", clock=lambda: 1.0)
        make_server({"tickets.list"}, refusals=led).call_tool("tickets.delete", {"ticket_id": 1})
        assert led.entries()[0].subject == "tickets.delete"
        assert led.entries()[0].subject_kind == "tool"

    def test_an_authorised_call_leaves_the_ledger_empty(
        self, make_server: ServerFactory, tmp_path: Path
    ) -> None:
        """The ledger holds refusals only. Nothing in it was ever permitted."""
        led = FileRefusalLedger(tmp_path / "ledger.jsonl", clock=lambda: 1.0)
        outcome = make_server({"fs.read"}, refusals=led).call_tool(
            "fs.read", {"path": "runbook.md"}
        )
        assert outcome.authorised
        assert led.entries() == ()

    def test_repeated_refusals_aggregate_and_still_refuse(
        self, make_server: ServerFactory, tmp_path: Path
    ) -> None:
        led = FileRefusalLedger(tmp_path / "ledger.jsonl", clock=lambda: 1.0)
        server = make_server({"fs.read"}, refusals=led)
        for _ in range(3):
            outcome = server.call_tool("fs.read", {"path": "../secrets.txt"})
            assert not outcome.authorised
        assert led.entries()[0].count == 3
        assert not server.call_tool("fs.read", {"path": "../secrets.txt"}).authorised

    def test_the_ledger_file_is_json_lines_and_append_only_on_disk(
        self, make_server: ServerFactory, tmp_path: Path
    ) -> None:
        path = tmp_path / "ledger.jsonl"
        led = FileRefusalLedger(path, clock=lambda: 9.0)
        server = make_server({"fs.read"}, refusals=led)
        server.call_tool("fs.read", {"path": "../secrets.txt"})
        first = path.read_bytes()
        server.call_tool("fs.read", {"path": "/etc/hosts"})
        assert path.read_bytes().startswith(first)
        lines = path.read_text(encoding="utf-8").strip().split("\n")
        assert [json.loads(line)["reason"] for line in lines] == [
            "path_outside_root",
            "path_outside_root",
        ]

    def test_the_rendered_ledger_carries_its_caveat(
        self, make_server: ServerFactory, tmp_path: Path
    ) -> None:
        led = FileRefusalLedger(tmp_path / "ledger.jsonl", clock=lambda: 1.0)
        make_server({"fs.read"}, refusals=led).call_tool("fs.read", {"path": "../secrets.txt"})
        assert "Nothing here grants anything." in render(led.entries())


class TestTheLedgerCannotLiveWhereTheAgentWrites:
    def test_a_server_refuses_a_ledger_inside_its_own_fs_root(
        self, workspace: Path, handlers: dict[str, object]
    ) -> None:
        """An agent with fs.write and a ledger in its root can forge the record."""
        led = FileRefusalLedger(workspace / "refusals.jsonl", clock=lambda: 1.0)
        task = Task(
            id="e2e-ledger",
            tool_scope=frozenset({"fs.write"}),
            fs_root=str(workspace),
            egress_allowlist=frozenset(),
            caps=Caps(max_calls=5, max_cost=5.0, max_wall_clock_s=10.0),
        )
        with pytest.raises(StoreWithinReachError, match="resolves inside fs_root"):
            build_server(
                task,
                reference_registry(),
                {"fs.write": handlers["fs.write"]},  # type: ignore[dict-item]
                refusals=led,
            )

    def test_a_ledger_beside_the_root_is_accepted(
        self, workspace: Path, tmp_path: Path, handlers: dict[str, object]
    ) -> None:
        """The check must be containment, not a prefix: `workspace-backup` is outside."""
        (tmp_path / "workspace-backup").mkdir()
        led = FileRefusalLedger(tmp_path / "workspace-backup" / "refusals.jsonl")
        task = Task(
            id="e2e-ledger-ok",
            tool_scope=frozenset({"fs.write"}),
            fs_root=str(workspace),
            egress_allowlist=frozenset(),
            caps=Caps(max_calls=5, max_cost=5.0, max_wall_clock_s=10.0),
        )
        server = build_server(
            task,
            reference_registry(),
            {"fs.write": handlers["fs.write"]},  # type: ignore[dict-item]
            refusals=led,
        )
        assert server.refusals is led

    def test_a_broker_built_without_a_ledger_reports_none_rather_than_a_throwaway(
        self, workspace: Path, handlers: dict[str, object]
    ) -> None:
        """A ledger that silently goes nowhere would read as an empty ledger."""
        task = Task(
            id="e2e-no-ledger",
            tool_scope=frozenset({"fs.read"}),
            fs_root=str(workspace),
            egress_allowlist=frozenset(),
            caps=Caps(max_calls=5, max_cost=5.0, max_wall_clock_s=10.0),
        )
        from agentboundary.mcp.server import BrokeredServer

        server = BrokeredServer(
            build_broker(task, reference_registry()),
            {"fs.read": handlers["fs.read"]},  # type: ignore[dict-item]
        )
        assert server.refusals is None
