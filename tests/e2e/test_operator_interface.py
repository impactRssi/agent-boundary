"""The operator interface, end to end (N-45).

Two things are asserted here that cannot be asserted in-process.

**The serving image does not contain the write path.** Every other test of this
property reads source. This one starts ``python -m agentboundary --task ...``
as a real OS process and reads its ``sys.modules``. The claim being checked is
not "the broker declines to grant a lease" but "the module that can write one
was never loaded" -- and a process image is the only place that claim is true
or false.

**The loop closes.** An operator grants a lease with the real command, a server
built by the real entry point reads it, and a call that was refused before the
grant is authorised during the window and refused again after it. A lease that
cannot be granted through the interface and honoured by the broker is a feature
with a gap in the middle, and the gap would be invisible to any test that used
the store directly.
"""

from __future__ import annotations

import io
import json
import subprocess
import sys
from pathlib import Path

import pytest

from agentboundary.__main__ import build_from_config, load_approvals, load_task
from agentboundary.__main__ import main as entry_point
from agentboundary.leases import FileLeaseStore
from agentboundary.mcp.server import BrokeredServer
from agentboundary.operator.cli import main as operator_main
from agentboundary.rotation import FileAdvisorySink

pytestmark = pytest.mark.e2e

NOW = 1_700_000_000.0
DAY = 86_400.0


def _write(path: Path, payload: object) -> Path:
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def _task_file(tmp_path: Path, workspace: Path, **extra: object) -> Path:
    return _write(
        tmp_path / "task.json",
        {
            "id": "nightly",
            "tool_scope": ["fs.read"],
            "fs_root": str(workspace),
            "caps": {"max_calls": 20, "max_cost": 20.0, "max_wall_clock_s": 60.0},
            **extra,
        },
    )


def _grant(store: Path, subject: Path, *, duration: str = "3d", now: float = NOW) -> str:
    stream = io.StringIO()
    code = operator_main(
        [
            "lease",
            "grant",
            "--store",
            str(store),
            "--kind",
            "path",
            "--subject",
            str(subject),
            "--duration",
            duration,
            "--granted-by",
            "operator@example.test",
            "--reason",
            "the nightly automation reads the credential directory",
        ],
        stream,
        now,
    )
    assert code == 0, stream.getvalue()
    return stream.getvalue()


class TestTheServingProcessCannotWriteALease:
    def test_a_real_serving_process_never_loads_the_operator_package(self, tmp_path: Path) -> None:
        """Not "does not call it": does not import it. Read out of sys.modules.

        The lease store is passed in, so the serving side is doing the most
        lease-adjacent thing it ever does -- reading a store, honouring a grant
        -- while still never loading the module that could create one.
        """
        workspace = tmp_path / "ws"
        workspace.mkdir()
        secrets = tmp_path / "secrets"
        secrets.mkdir()
        store = tmp_path / "leases.jsonl"
        _grant(store, secrets)
        task = _task_file(tmp_path, workspace)

        probe = (
            "import sys;"
            "from agentboundary.__main__ import main;"
            f"main(['--task', {str(task)!r},"
            f" '--audit', {str(tmp_path / 'trace.jsonl')!r},"
            f" '--leases', {str(store)!r}, '--dry-run']);"
            "print(sorted(name for name in sys.modules"
            " if name.startswith('agentboundary.operator')))"
        )
        completed = subprocess.run(  # noqa: S603 -- fixed argv, no shell
            [sys.executable, "-c", probe],
            capture_output=True,
            text=True,
            timeout=60,
            check=True,
        )

        loaded = json.loads(completed.stdout.strip().replace("'", '"'))
        assert loaded == [], (
            f"a serving process loaded {loaded}. agentboundary.operator.grant holds the "
            f"only code that writes a lease; a steered loop runs inside this image."
        )

    def test_the_serving_process_does_load_the_lease_reader(self, tmp_path: Path) -> None:
        """Guards the assertion above against passing for the wrong reason."""
        workspace = tmp_path / "ws"
        workspace.mkdir()
        task = _task_file(tmp_path, workspace)
        probe = (
            "import sys;"
            "from agentboundary.__main__ import main;"
            f"main(['--task', {str(task)!r},"
            f" '--audit', {str(tmp_path / 'trace.jsonl')!r}, '--dry-run']);"
            "print('agentboundary.leases' in sys.modules)"
        )
        completed = subprocess.run(  # noqa: S603 -- fixed argv, no shell
            [sys.executable, "-c", probe],
            capture_output=True,
            text=True,
            timeout=60,
            check=True,
        )
        assert completed.stdout.strip().endswith("True")


class TestAGrantedLeaseIsHonouredAndThenIsNot:
    def _server_reading(self, tmp_path: Path, workspace: Path, store: Path) -> BrokeredServer:
        return build_from_config(
            load_task(_task_file(tmp_path, workspace)),
            load_approvals(None),
            tmp_path / "trace.jsonl",
            None,
            leases_path=store,
        )

    def test_the_path_is_refused_before_the_grant(self, tmp_path: Path) -> None:
        workspace = tmp_path / "ws"
        workspace.mkdir()
        secrets = tmp_path / "secrets"
        secrets.mkdir()
        (secrets / "env").write_text("TOKEN=AKIAEXAMPLE", encoding="utf-8")
        store = tmp_path / "leases.jsonl"
        store.write_text("", encoding="utf-8")

        server = self._server_reading(tmp_path, workspace, store)
        outcome = server.call_tool("fs.read", {"path": "../secrets/env"})

        assert not outcome.authorised
        assert outcome.refusal_reason == "path_outside_root"

    def test_the_grant_makes_exactly_that_path_reachable(self, tmp_path: Path) -> None:
        workspace = tmp_path / "ws"
        workspace.mkdir()
        secrets = tmp_path / "secrets"
        secrets.mkdir()
        (secrets / "env").write_text("TOKEN=AKIAEXAMPLE", encoding="utf-8")
        store = tmp_path / "leases.jsonl"

        _grant(store, secrets, now=FileLeaseStore(store).now())

        server = self._server_reading(tmp_path, workspace, store)
        assert server.call_tool("fs.read", {"path": "../secrets/env"}).authorised

    def test_a_sibling_of_the_leased_directory_stays_refused(self, tmp_path: Path) -> None:
        """One typed subject widens one location. Not its neighbour, not its parent."""
        workspace = tmp_path / "ws"
        workspace.mkdir()
        secrets = tmp_path / "secrets"
        secrets.mkdir()
        backup = tmp_path / "secrets-backup"
        backup.mkdir()
        (backup / "env").write_text("TOKEN=AKIAEXAMPLE", encoding="utf-8")
        store = tmp_path / "leases.jsonl"

        _grant(store, secrets, now=FileLeaseStore(store).now())

        server = self._server_reading(tmp_path, workspace, store)
        outcome = server.call_tool("fs.read", {"path": "../secrets-backup/env"})
        assert not outcome.authorised
        assert outcome.refusal_reason == "path_outside_root"

    def test_the_same_call_is_refused_again_once_the_lease_expires(self, tmp_path: Path) -> None:
        """Expiry fails closed with no further operator action. That is the point
        of a lease: the boundary comes back on its own."""
        workspace = tmp_path / "ws"
        workspace.mkdir()
        secrets = tmp_path / "secrets"
        secrets.mkdir()
        (secrets / "env").write_text("TOKEN=AKIAEXAMPLE", encoding="utf-8")
        store = tmp_path / "leases.jsonl"

        # Granted three days ago for one hour: written by the real command, and
        # already over by the time the broker reads it.
        _grant(store, secrets, duration="1h", now=FileLeaseStore(store).now() - 3 * DAY)

        server = self._server_reading(tmp_path, workspace, store)
        outcome = server.call_tool("fs.read", {"path": "../secrets/env"})
        assert not outcome.authorised
        assert outcome.refusal_reason == "path_outside_root"


class TestExpiryOwesRotationAdviceThroughTheEntryPoint:
    def test_building_a_server_sweeps_an_expired_credential_lease(self, tmp_path: Path) -> None:
        workspace = tmp_path / "ws"
        workspace.mkdir()
        secrets = tmp_path / "secrets"
        secrets.mkdir()
        store = tmp_path / "leases.jsonl"
        advisories = tmp_path / "advisories.jsonl"

        _grant(store, secrets, duration="1h", now=FileLeaseStore(store).now() - 3 * DAY)

        build_from_config(
            load_task(_task_file(tmp_path, workspace)),
            load_approvals(None),
            tmp_path / "trace.jsonl",
            None,
            leases_path=store,
            advisories_path=advisories,
        )

        written = FileAdvisorySink(advisories).advisories()
        assert len(written) == 1
        assert str(secrets.resolve()) in written[0].message
        assert "not evidence that nothing was taken" in written[0].message

    def test_lease_list_reports_the_same_rotation_the_sweep_would(self, tmp_path: Path) -> None:
        secrets = tmp_path / "secrets"
        secrets.mkdir()
        store = tmp_path / "leases.jsonl"
        _grant(store, secrets, duration="1h", now=NOW)

        stream = io.StringIO()
        assert operator_main(["lease", "list", "--store", str(store)], stream, NOW + DAY) == 0

        printed = stream.getvalue()
        assert "EXPIRED" in printed
        assert "Rotate every secret stored under" in printed


class TestOneExecutableRoutesToTwoPrograms:
    """`agent-boundary` is the console script for both. The routing is the seam."""

    def test_the_refusals_command_is_reachable_through_the_entry_point(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        ledger = tmp_path / "refusals.jsonl"
        ledger.write_text("", encoding="utf-8")
        assert entry_point(["refusals", "--ledger", str(ledger)]) == 0
        assert "not a request for permission" in capsys.readouterr().out

    def test_the_lease_commands_are_reachable_through_the_entry_point(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        store = tmp_path / "leases.jsonl"
        _grant(store, tmp_path / "secrets", now=NOW)
        assert entry_point(["lease", "list", "--store", str(store)]) == 0
        assert "delete the lease's line" in capsys.readouterr().out

    def test_the_serve_form_still_works_with_no_subcommand_word(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Every existing deployment writes `--task ...`. Adding a required
        `serve` word would have been a breaking change dressed as tidiness."""
        workspace = tmp_path / "ws"
        workspace.mkdir()
        code = entry_point(
            [
                "--task",
                str(_task_file(tmp_path, workspace)),
                "--audit",
                str(tmp_path / "trace.jsonl"),
                "--dry-run",
            ]
        )
        assert code == 0
        assert "fs.read" in capsys.readouterr().err

    def test_the_serve_summary_reports_the_lease_store_it_will_consult(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        workspace = tmp_path / "ws"
        workspace.mkdir()
        secrets = tmp_path / "secrets"
        secrets.mkdir()
        store = tmp_path / "leases.jsonl"
        _grant(store, secrets, now=NOW)

        entry_point(
            [
                "--task",
                str(_task_file(tmp_path, workspace)),
                "--audit",
                str(tmp_path / "trace.jsonl"),
                "--leases",
                str(store),
                "--dry-run",
            ]
        )

        reported = capsys.readouterr().err
        assert str(store) in reported
        assert "read-only here" in reported

    def test_the_serve_summary_reports_the_scope_a_tool_lease_widened(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """The scope printed is the served one, not the one the task file asked
        for. Printing the file's version would understate what the agent holds."""
        workspace = tmp_path / "ws"
        workspace.mkdir()
        store = tmp_path / "leases.jsonl"
        stream = io.StringIO()
        assert (
            operator_main(
                [
                    "lease",
                    "grant",
                    "--store",
                    str(store),
                    "--kind",
                    "tool",
                    "--subject",
                    "fs.write",
                    "--duration",
                    "1h",
                    "--granted-by",
                    "operator@example.test",
                    "--reason",
                    "the migration writes into the workspace",
                ],
                stream,
                FileLeaseStore(store).now(),
            )
            == 0
        ), stream.getvalue()

        entry_point(
            [
                "--task",
                str(_task_file(tmp_path, workspace)),
                "--audit",
                str(tmp_path / "trace.jsonl"),
                "--leases",
                str(store),
                "--dry-run",
            ]
        )

        assert "fs.write" in capsys.readouterr().err


class TestALeaseCannotConjureACapability:
    def test_a_tool_lease_for_a_tool_with_no_handler_refuses_to_start(self, tmp_path: Path) -> None:
        """Loudly, at construction. Starting and failing at dispatch would read
        to an operator as a broker fault rather than as a missing handler."""
        workspace = tmp_path / "ws"
        workspace.mkdir()
        store = tmp_path / "leases.jsonl"
        stream = io.StringIO()
        assert (
            operator_main(
                [
                    "lease",
                    "grant",
                    "--store",
                    str(store),
                    "--kind",
                    "tool",
                    "--subject",
                    "tickets.delete",
                    "--duration",
                    "1h",
                    "--granted-by",
                    "operator@example.test",
                    "--reason",
                    "cleaning up duplicate tickets",
                ],
                stream,
                FileLeaseStore(store).now(),
            )
            == 0
        ), stream.getvalue()

        with pytest.raises(SystemExit, match="no handler"):
            build_from_config(
                load_task(_task_file(tmp_path, workspace)),
                load_approvals(None),
                tmp_path / "trace.jsonl",
                None,
                leases_path=store,
            )


class TestTheStoresStayOutOfTheAgentsReach:
    def test_a_lease_store_inside_the_task_root_refuses_to_start(self, tmp_path: Path) -> None:
        """An agent that can write its own grants has no boundary at all."""
        workspace = tmp_path / "ws"
        workspace.mkdir()
        store = workspace / "leases.jsonl"
        _grant(store, tmp_path / "secrets", now=NOW)

        with pytest.raises(Exception, match="resolves inside fs_root"):
            build_from_config(
                load_task(_task_file(tmp_path, workspace)),
                load_approvals(None),
                tmp_path / "trace.jsonl",
                None,
                leases_path=store,
            )

    def test_a_refusal_ledger_inside_the_task_root_refuses_to_start(self, tmp_path: Path) -> None:
        workspace = tmp_path / "ws"
        workspace.mkdir()
        with pytest.raises(Exception, match="resolves inside fs_root"):
            build_from_config(
                load_task(_task_file(tmp_path, workspace)),
                load_approvals(None),
                tmp_path / "trace.jsonl",
                None,
                refusals_path=workspace / "refusals.jsonl",
            )


class TestRefusalsFlowFromTheBrokerToTheCommand:
    def test_a_refused_call_appears_in_what_the_operator_reads(self, tmp_path: Path) -> None:
        """The whole loop: the broker refuses, the ledger records, the command
        prints it -- with the sentence saying it is not a request for permission."""
        workspace = tmp_path / "ws"
        workspace.mkdir()
        (tmp_path / "secret.txt").write_text("AKIAEXAMPLE", encoding="utf-8")
        ledger = tmp_path / "refusals.jsonl"

        server = build_from_config(
            load_task(_task_file(tmp_path, workspace)),
            load_approvals(None),
            tmp_path / "trace.jsonl",
            None,
            refusals_path=ledger,
        )
        assert not server.call_tool("fs.read", {"path": "../secret.txt"}).authorised

        stream = io.StringIO()
        assert operator_main(["refusals", "--ledger", str(ledger)], stream, NOW) == 0

        printed = stream.getvalue()
        assert "path_outside_root" in printed
        assert "secret.txt" in printed
        assert "not a request for permission" in printed
        assert "type the subject out" in printed
