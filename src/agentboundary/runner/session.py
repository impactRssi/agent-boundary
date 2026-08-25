"""The tool surface of an agent session, derived rather than filtered (N-50).

This module is I1 turned on the harness. ``ADR-0002`` argues that an
out-of-scope tool must be absent from the model's schema rather than refused at
call time, and the argument applies with equal force to whatever runtime holds
the brokered server: routing some calls through a broker while a native
``Bash`` or ``Read`` handle stays open in the same session demonstrates nothing
about the broker. A demonstration is only worth reading if the brokered tools
are the *only* tools.

So the surface is **derived**. :class:`SessionSpec` has no field in which a
built-in tool could be requested, and every name it does carry must be a
qualified tool of this session's own brokered server. A native handle is not
removed from the surface; there is no representable :class:`SessionSpec` that
contains one. That is the difference between a control and a filter, and it is
why :data:`NATIVE_TOOL_FAMILIES` below is documentation and a test fixture --
never a blocklist consulted on the way to a decision.

Standard library only, deliberately. The SDK binding lives next door in
:mod:`agentboundary.runner.claude`; this module is where the property is
decided, so it stays on the dependency-free path that
``tests/unit/test_evidence_is_not_a_benchmark.py`` guards (ADR-0009 §6).
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

__all__ = [
    "MCP_QUALIFIER",
    "NATIVE_TOOL_FAMILIES",
    "NO_BUILTIN_TOOLS",
    "SEPARATOR",
    "BrokeredServerSpec",
    "SessionSpec",
    "SessionSurfaceError",
    "qualify",
    "session_spec",
]

#: How the Claude Code CLI names a tool served by an MCP server:
#: ``mcp__<server>__<tool>``. Every name on a brokered session's surface
#: carries it, and no built-in tool does -- which is what makes the prefix test
#: in :class:`SessionSpec` sufficient rather than merely indicative.
MCP_QUALIFIER = "mcp__"

#: The separator between the server name and the tool name in that convention.
SEPARATOR = "__"

#: The base set of built-in tools a brokered session is given: none.
#:
#: A tuple rather than a flag, and empty rather than absent, because the SDK
#: distinguishes the two: ``None`` means "the default set", ``[]`` means "no
#: built-in tools". Leaving it to a default is how a session quietly acquires a
#: filesystem.
NO_BUILTIN_TOOLS: tuple[str, ...] = ()

#: Built-in tool families whose presence would defeat the demonstration --
#: filesystem, shell, and fetch handles reaching the same machine the broker is
#: confining.
#:
#: **This is not the control.** Nothing on the authorisation path, and nothing
#: on the surface-construction path, reads it. A blocklist of native tool names
#: would be exactly the call-time-filter shape ``ADR-0002`` rejects, and it
#: would go stale the first time the runtime gained a tool nobody here had
#: heard of. The control is that :class:`SessionSpec` cannot represent a
#: built-in tool at all. This set exists so tests can name what they assert the
#: absence of, and so a reader knows what the property is worth.
NATIVE_TOOL_FAMILIES = frozenset(
    {
        "Bash",
        "BashOutput",
        "Edit",
        "Glob",
        "Grep",
        "KillShell",
        "NotebookEdit",
        "Read",
        "Task",
        "WebFetch",
        "WebSearch",
        "Write",
    }
)


class SessionSurfaceError(ValueError):
    """A session was asked for a tool surface it must not be able to have.

    Raised at construction, never at call time. A caller that sees this has a
    configuration defect; an agent can never provoke it, because the agent does
    not build the session.
    """


def qualify(server_name: str, tool_name: str) -> str:
    """Name ``tool_name`` as the runtime sees it when ``server_name`` serves it.

    If this convention is ever wrong the failure is a tool that prompts for
    permission instead of running: the session's surface is unchanged and no
    effect occurs that would not otherwise. Fail-closed in the only direction a
    naming mistake here can go.
    """
    return f"{MCP_QUALIFIER}{server_name}{SEPARATOR}{tool_name}"


@dataclass(frozen=True, slots=True)
class BrokeredServerSpec:
    """How to spawn the broker the session will talk to.

    A subprocess, not an in-process object. The broker's whole claim is that
    the tools live *behind* it rather than beside it (ADR-0005), and a runner
    that imported the handlers to save a process boundary would have handed
    itself the second route this node exists to close.
    """

    name: str
    command: str
    args: tuple[str, ...] = ()
    env: Mapping[str, str] | None = None

    def __post_init__(self) -> None:
        if not self.name:
            msg = "a brokered server needs a name; the session's tool names are built from it"
            raise SessionSurfaceError(msg)
        if SEPARATOR in self.name:
            # `mcp__a__b` would qualify ambiguously: (server 'a', tool 'b') and
            # (server 'a__b', tool ...) overlap, and an overlapping name space
            # is where a prefix test stops being a proof.
            msg = (
                f"server name {self.name!r} contains {SEPARATOR!r}, the separator qualified "
                f"tool names use. Choose a name without it, so the prefix test that keeps "
                f"native handles off this session's surface stays unambiguous."
            )
            raise SessionSurfaceError(msg)

    def as_mcp_config(self) -> dict[str, Any]:
        """The stdio server entry, in the shape the SDK's ``mcp_servers`` takes."""
        config: dict[str, Any] = {
            "type": "stdio",
            "command": self.command,
            "args": list(self.args),
        }
        if self.env is not None:
            config["env"] = dict(self.env)
        return config


@dataclass(frozen=True, slots=True)
class SessionSpec:
    """Everything a brokered session is, as data a test can read without a model.

    Note what is **not** here: any field naming a built-in tool. The surface is
    ``tools``, ``tools`` is checked to hold only this session's own brokered
    names, and the built-in set is the constant :data:`NO_BUILTIN_TOOLS`. There
    is no argument, no override and no configuration file that widens it --
    which is the point, because a control an operator can switch off is one an
    operator eventually switches off.
    """

    server: BrokeredServerSpec
    tools: tuple[str, ...]
    cwd: Path | None = None

    def __post_init__(self) -> None:
        prefix = f"{MCP_QUALIFIER}{self.server.name}{SEPARATOR}"
        offenders = sorted(name for name in self.tools if not name.startswith(prefix))
        if offenders:
            msg = (
                f"a session surface may name only tools served by {self.server.name!r} "
                f"(prefix {prefix!r}); refusing {offenders}. A built-in filesystem, shell or "
                f"fetch handle is not something this session declines to use -- it is "
                f"something it cannot be given (I1, ADR-0002)."
            )
            raise SessionSurfaceError(msg)
        bare = sorted(name for name in self.tools if name == prefix)
        if bare:
            msg = (
                f"a session surface carries a qualified prefix with no tool behind it: {bare}. "
                f"An empty tool name is not a handle to anything and hides which listing "
                f"produced it."
            )
            raise SessionSurfaceError(msg)
        if len(set(self.tools)) != len(self.tools):
            # Determinism: two spellings of one handle make the rendered
            # surface depend on iteration order rather than on the task.
            msg = f"a session surface repeats a tool: {sorted(self.tools)}"
            raise SessionSurfaceError(msg)

    @property
    def builtin_tools(self) -> tuple[str, ...]:
        """Always empty. A property, not a field, so nothing can assign to it."""
        return NO_BUILTIN_TOOLS

    def sdk_options(self) -> dict[str, Any]:
        """The session's configuration, as plain data.

        Returned as a mapping rather than as an SDK object so every
        security-relevant value here is assertable without the SDK installed,
        without a model and without the network.
        :mod:`agentboundary.runner.claude` does nothing but hand this to the SDK
        constructor.

        Each entry is set explicitly even where it matches today's default. A
        default is a decision taken in another repository on another release
        schedule, and every one of the defaults below widens this session's
        surface when it changes.
        """
        return {
            # The load-bearing line. `[]` is "no built-in tools"; `None` is
            # "all of them". That distinction is the node.
            "tools": list(NO_BUILTIN_TOOLS),
            # **Not a scope, and never mistake it for one.** The SDK documents
            # this option as "auto-approved without prompting; does not restrict
            # Claude to only these tools". Building the surface out of it would
            # be precisely the call-time filter over a live dispatch table that
            # `ADR-0002` rejects -- the handle would still be there. It appears
            # here only so the brokered tools run without an interactive prompt,
            # and every name in it is already scoped by the broker on the far
            # side of the transport. Derived from the broker's own listing,
            # never authored.
            "allowed_tools": list(self.tools),
            # Deliberately empty. A blocklist of native tool names would say the
            # capability was reachable and we chose not to use it. It is also
            # unnecessary: `tools` above is what removes the handles, and a
            # blocklist would have to be kept in step with a runtime whose tool
            # set this repository does not control.
            "disallowed_tools": [],
            # Deny anything that was not pre-approved rather than prompting for
            # it. A prompt is not a control in a non-interactive run -- it is a
            # process waiting on a human who is not there, and the failure mode
            # of "waiting" is that somebody eventually answers yes.
            "permission_mode": "dontAsk",
            "mcp_servers": {self.server.name: self.server.as_mcp_config()},
            # Ignore every MCP server the runtime would otherwise discover --
            # project `.mcp.json`, user settings, plugin-provided servers.
            # Without this the surface is whatever happens to be configured on
            # the machine it runs on, which is not a surface anyone can attest
            # to.
            "strict_mcp_config": True,
            # No user, project or local settings. Those carry skills,
            # permissions and further servers; loading them puts the tool
            # surface outside this file's control.
            "setting_sources": [],
            "plugins": [],
            # A subagent is a session with its own surface. None is declared, so
            # none inherits one.
            "agents": None,
            "skills": None,
            "add_dirs": [],
            "cwd": None if self.cwd is None else str(self.cwd),
        }

    def render(self) -> str:
        """The surface, for an operator checking it before spending money on a run."""
        return "\n".join(
            [
                f"agent-boundary runner: server {self.server.name!r}",
                f"  spawn:    {self.server.command} {' '.join(self.server.args)}".rstrip(),
                f"  builtin:  {', '.join(self.builtin_tools) or '(none: no native handle exists)'}",
                f"  brokered: {', '.join(self.tools) or '(nothing: the task scopes no tool)'}",
                "  settings: (none: strict MCP config, no user/project/local sources)",
            ]
        )


def session_spec(
    server_name: str,
    command: str,
    args: Sequence[str],
    brokered_tools: Iterable[str],
    cwd: Path | None = None,
    env: Mapping[str, str] | None = None,
) -> SessionSpec:
    """Build a session surface from the broker's own tool listing.

    ``brokered_tools`` are the bare names the broker returned from
    ``tools/list`` -- the task's resolved scope, read off the wire rather than
    re-derived from the task file. Re-deriving it would create a second source
    of truth for what the session may reach, and a second source of truth is
    the shape this node exists to remove. It also gets the answer wrong the
    moment a tool lease widens the scope, because the widening happens inside
    the broker.

    Sorted, so the same task and the same listing produce the same spec
    whatever order the transport returned them in (NFR-002).
    """
    server = BrokeredServerSpec(name=server_name, command=command, args=tuple(args), env=env)
    return SessionSpec(
        server=server,
        tools=tuple(sorted(qualify(server_name, name) for name in brokered_tools)),
        cwd=cwd,
    )
