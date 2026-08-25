"""A native tool has no handle in a brokered session (N-50, I1).

What this tier asserts, and what it deliberately does not. It does **not** call
a native tool and check that it was refused. That test would pass on a session
holding a live ``Bash`` handle behind a permission filter, which is exactly the
shape ``ADR-0002`` rejects -- and a passing test asserting the wrong property is
worse than no test, because it makes the wrong property look measured. What is
asserted is **absence**: the session's whole tool surface is read off a real
broker over a real transport, and no native filesystem, shell or fetch handle
is anywhere in it or in the options built from it.

Offline, and that is load-bearing rather than incidental. ``ADR-0009`` separates
reproducible offline measurement from model-in-the-loop evidence and forbids the
second from gating a build. So:

* The transport is real -- ``python -m agentboundary`` in a separate OS process,
  driven by the real MCP client over real pipes. No mock at the boundary.
* The SDK is real -- ``ClaudeAgentOptions`` is constructed by the installed
  ``claude-agent-sdk``, which is what catches the API drift that left
  ``mcp/stdio.py`` broken and uncovered until N-30.
* No model is called and no socket is opened. Constructing options, and even
  constructing the client, spawns nothing; only entering the client's context
  would, and nothing here does.
"""

from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
from claude_agent_sdk import ClaudeAgentOptions

from agentboundary.runner import NATIVE_TOOL_FAMILIES, SessionSpec, qualify
from agentboundary.runner.__main__ import SERVER_NAME, broker_argv
from agentboundary.runner.claude import session_client, session_options
from agentboundary.runner.discovery import discover_brokered_tools, discover_session

pytestmark = pytest.mark.e2e

#: Failsafe only, against a child that deadlocks. A healthy handshake over a
#: local pipe completes in milliseconds and no assertion depends on this.
_HUNG_CHILD_TIMEOUT_S = 120.0

#: The task's scope. Note what is absent and stays absent: anything that writes,
#: deletes, or reaches the network.
SCOPE = ("fs.read", "tickets.get", "tickets.comment")

_PROJECT_CONFIG = Path(__file__).resolve().parents[2] / "pyproject.toml"


def _child_environment() -> dict[str, str]:
    """The child's environment, with coverage measurement propagated into it.

    Same reasoning as ``test_stdio_transport.py``: the broker runs in a child,
    so without this hook the code under test reports as uncovered while being
    fully exercised.
    """
    environment = {**os.environ}
    try:
        import coverage
    except ImportError:  # pragma: no cover -- coverage is a dev-group dependency
        return environment
    active = coverage.Coverage.current()
    if active is not None and _PROJECT_CONFIG.exists():
        environment["COVERAGE_PROCESS_START"] = str(_PROJECT_CONFIG)
        data_file = active.config.data_file
        if data_file:
            environment["COVERAGE_FILE"] = str(Path(data_file).resolve())
    return environment


@pytest.fixture(scope="module")
def workspace(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Path]:
    root = tmp_path_factory.mktemp("runner")
    work = root / "workspace"
    work.mkdir()
    (work / "runbook.md").write_text("# Runbook\nReset the password.\n", encoding="utf-8")
    task = root / "task.json"
    task.write_text(
        json.dumps(
            {
                "id": "brokered-session",
                "tool_scope": list(SCOPE),
                "fs_root": str(work),
                "caps": {"max_calls": 20, "max_cost": 20.0, "max_wall_clock_s": 600.0},
            }
        ),
        encoding="utf-8",
    )
    tickets = root / "tickets.json"
    tickets.write_text(json.dumps([{"id": 1, "subject": "s", "body": "b"}]), encoding="utf-8")
    return {"root": root, "task": task, "tickets": tickets, "audit": root / "audit.jsonl"}


@pytest.fixture(scope="module")
def spec(workspace: dict[str, Path]) -> SessionSpec:
    """The session surface, resolved from a live broker over a real transport.

    Module-scoped: spawning the broker is the expensive part, and the surface
    is fixed. Every assertion below reads this one resolved session.
    """
    return asyncio.run(
        asyncio.wait_for(
            discover_session(
                server_name=SERVER_NAME,
                command=sys.executable,
                args=broker_argv(
                    task=workspace["task"],
                    audit=workspace["audit"],
                    tickets=workspace["tickets"],
                ),
                env=_child_environment(),
            ),
            timeout=_HUNG_CHILD_TIMEOUT_S,
        )
    )


@pytest.fixture(scope="module")
def options(spec: SessionSpec) -> ClaudeAgentOptions:
    """The real SDK options object. Constructing it calls no model.

    ``session_options`` is annotated ``-> Any`` so that
    :mod:`agentboundary.runner.claude` type-checks without the SDK installed.
    The narrowing therefore happens here, and it is an assertion rather than a
    cast: if the binding ever returned something else, this tier should say so
    instead of silently believing the annotation.
    """
    built = session_options(spec)
    assert isinstance(built, ClaudeAgentOptions)
    return built


class TestNoNativeHandleExistsToBeNamed:
    """The node, asserted as absence. Nothing here calls a tool and reads a refusal."""

    @pytest.mark.parametrize("native", sorted(NATIVE_TOOL_FAMILIES))
    def test_no_native_tool_is_on_the_sessions_surface(
        self, spec: SessionSpec, native: str
    ) -> None:
        assert native not in spec.tools

    def test_the_built_in_tool_set_is_empty_rather_than_defaulted(
        self, options: ClaudeAgentOptions
    ) -> None:
        """The load-bearing assertion, made against the real SDK object.

        ``[]`` means no built-in tools; ``None`` means every one of them. The
        SDK distinguishes the two, so an assertion that only checked
        falsiness would pass on the configuration this node exists to prevent.
        """
        assert options.tools == []
        assert options.tools is not None

    @pytest.mark.parametrize("native", sorted(NATIVE_TOOL_FAMILIES))
    def test_no_native_tool_is_named_anywhere_in_the_session_options(
        self, options: ClaudeAgentOptions, native: str
    ) -> None:
        """Absence across the whole configuration, not only the tool list.

        A native handle reintroduced through an allowed pattern, a plugin, or a
        subagent definition would be just as reachable as one in ``tools``.
        """
        surfaces: list[Any] = [
            options.tools,
            options.allowed_tools,
            options.disallowed_tools,
            options.plugins,
            options.agents,
            options.skills,
            options.add_dirs,
            options.setting_sources,
        ]
        assert native not in repr(surfaces)

    def test_the_only_tools_are_this_brokers_tools(self, options: ClaudeAgentOptions) -> None:
        prefix = f"mcp__{SERVER_NAME}__"
        assert options.allowed_tools
        assert all(name.startswith(prefix) for name in options.allowed_tools)

    def test_the_broker_itself_lists_no_native_tool(self, spec: SessionSpec) -> None:
        """Over the wire: there is nothing native behind the transport either.

        The session has no native handle *and* the one server it can reach does
        not serve a native tool under any name. Both halves are needed -- a
        broker that happened to expose a shell would make the empty built-in set
        worthless.
        """
        bare = {name.removeprefix(f"mcp__{SERVER_NAME}__") for name in spec.tools}
        assert not (bare & NATIVE_TOOL_FAMILIES)


class TestNoSecondRouteToTheSameMachine:
    """Routing some calls through a broker while a second route stays open
    demonstrates nothing. These are the routes that reopen without a code edit."""

    def test_only_the_brokered_server_is_configured(self, options: ClaudeAgentOptions) -> None:
        # The SDK also accepts a path to an MCP config file here. That form
        # would put the session's servers in a file on the machine rather than
        # in this repository, so the inline mapping is the shape asserted.
        assert isinstance(options.mcp_servers, dict)
        assert set(options.mcp_servers) == {SERVER_NAME}

    def test_ambient_mcp_configuration_is_ignored(self, options: ClaudeAgentOptions) -> None:
        """A project `.mcp.json` on the machine must not add a server."""
        assert options.strict_mcp_config is True

    def test_no_filesystem_settings_are_loaded(self, options: ClaudeAgentOptions) -> None:
        """User, project and local settings carry skills, permissions and servers."""
        assert options.setting_sources == []

    def test_no_plugin_and_no_subagent_brings_its_own_surface(
        self, options: ClaudeAgentOptions
    ) -> None:
        assert options.plugins == []
        assert options.agents is None
        assert options.skills is None

    def test_no_extra_directory_is_added(self, options: ClaudeAgentOptions) -> None:
        assert options.add_dirs == []

    def test_an_unapproved_call_is_denied_rather_than_prompted_for(
        self, options: ClaudeAgentOptions
    ) -> None:
        assert options.permission_mode == "dontAsk"


class TestTheSurfaceIsTheBrokersOwnListing:
    def test_the_surface_is_exactly_the_scope_the_broker_resolved(self, spec: SessionSpec) -> None:
        assert set(spec.tools) == {qualify(SERVER_NAME, name) for name in SCOPE}

    def test_it_was_read_from_the_broker_rather_than_from_the_task_file(
        self, workspace: dict[str, Path]
    ) -> None:
        """The listing comes off the wire, so a lease-widened scope is included.

        Asserted by reading the same listing directly: the surface and the
        broker agree because they are the same answer, not two derivations that
        happen to match.
        """
        listed = asyncio.run(
            asyncio.wait_for(
                discover_brokered_tools(
                    command=sys.executable,
                    args=broker_argv(
                        task=workspace["task"],
                        audit=workspace["audit"],
                        tickets=workspace["tickets"],
                    ),
                    env=_child_environment(),
                ),
                timeout=_HUNG_CHILD_TIMEOUT_S,
            )
        )
        assert listed == tuple(sorted(SCOPE))


class TestTheSdkBindingStillMatchesTheSdk:
    """`mcp/stdio.py` drifted against a removed API while sitting at 0% coverage.
    These construct the real objects so that the next such drift fails here."""

    def test_the_options_object_is_the_sdks_own_type(self, options: ClaudeAgentOptions) -> None:
        assert isinstance(options, ClaudeAgentOptions)

    def test_every_option_the_runner_sets_is_still_an_option(self, spec: SessionSpec) -> None:
        """Passed by `**`, so a renamed or removed field raises here rather than
        being silently dropped into a session that runs with a default surface."""
        accepted = set(ClaudeAgentOptions.__dataclass_fields__)
        assert set(spec.sdk_options()) <= accepted

    def test_a_client_can_be_constructed_without_spawning_anything(self, spec: SessionSpec) -> None:
        """Construction is inert; only entering its context reaches the network."""
        client = session_client(spec)
        assert client.options.tools == []


def _run_runner(workspace: dict[str, Path], *extra: str) -> subprocess.CompletedProcess[str]:
    """The runner entry point as a real subprocess, which spawns a real broker."""
    return subprocess.run(  # noqa: S603 -- fixed argv, no shell
        [
            sys.executable,
            "-m",
            "agentboundary.runner",
            "--task",
            str(workspace["task"]),
            "--audit",
            str(workspace["audit"]),
            "--tickets",
            str(workspace["tickets"]),
            *extra,
        ],
        capture_output=True,
        text=True,
        timeout=_HUNG_CHILD_TIMEOUT_S,
        env=_child_environment(),
        check=False,
    )


@pytest.fixture(scope="module")
def dry_run(workspace: dict[str, Path]) -> subprocess.CompletedProcess[str]:
    return _run_runner(workspace, "--dry-run")


class TestTheOperatorCanCheckTheSurfaceBeforePayingForARun:
    """`--dry-run` as a real subprocess: spawn, handshake, list, print, exit."""

    def test_it_exits_cleanly(self, dry_run: subprocess.CompletedProcess[str]) -> None:
        assert dry_run.returncode == 0, dry_run.stderr

    def test_it_reports_that_no_native_handle_exists(
        self, dry_run: subprocess.CompletedProcess[str]
    ) -> None:
        assert "(none: no native handle exists)" in dry_run.stderr

    @pytest.mark.parametrize("native", sorted(NATIVE_TOOL_FAMILIES))
    def test_no_native_tool_appears_in_what_the_operator_is_shown(
        self, dry_run: subprocess.CompletedProcess[str], native: str
    ) -> None:
        assert native not in dry_run.stderr

    def test_it_shows_the_brokered_tools(self, dry_run: subprocess.CompletedProcess[str]) -> None:
        for name in SCOPE:
            assert qualify(SERVER_NAME, name) in dry_run.stderr

    def test_the_banner_does_not_pollute_stdout(
        self, dry_run: subprocess.CompletedProcess[str]
    ) -> None:
        assert dry_run.stdout == ""


class TestARunWithoutAPromptFailsClosed:
    def test_it_refuses_rather_than_starting_a_billed_empty_session(
        self, workspace: dict[str, Path]
    ) -> None:
        """No --prompt and no --dry-run: refuse, do not start and bill for it."""
        completed = _run_runner(workspace)
        assert completed.returncode == 2
        assert "refusing to start" in completed.stderr
