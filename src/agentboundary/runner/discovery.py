"""Ask the broker what it serves, over the transport the session will use (N-50).

The session's tool surface has to come from somewhere, and where it comes from
is a security decision rather than a convenience one. Two sources were
available:

* Read ``tool_scope`` out of the task file. Cheap, offline, and wrong twice
  over. It is a second source of truth for what the session may reach -- the
  shape ``ADR-0002`` argues against -- and it disagrees with the broker
  whenever a tool lease widens the scope, because :func:`leased_task` applies
  that widening inside :func:`~agentboundary.mcp.server.build_broker`.
* Ask the broker. One source of truth, already authoritative, and the answer is
  literally the list the session will see.

This module does the second. It spawns the same ``python -m agentboundary``
process the session will spawn, completes a real MCP handshake with it, reads
``tools/list``, and shuts it down. No model, no network -- stdio pipes to a
child process on the same machine.

Requires the ``runner`` extra::

    pip install "agent-boundary[runner]"
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from pathlib import Path

from agentboundary.runner.session import SessionSpec, session_spec

__all__ = ["discover_brokered_tools", "discover_session"]

_MISSING_SDK = (
    "Discovering the brokered tool surface needs the optional 'runner' extra:\n"
    '    pip install "agent-boundary[runner]"\n'
    "The core package carries zero runtime dependencies by design (ADR-0005)."
)

#: Failsafe only. The child is a local process reached over a pipe; a healthy
#: handshake completes in milliseconds. This exists so a broker that deadlocks
#: fails the caller instead of hanging it, and nothing asserts on it.
HANDSHAKE_TIMEOUT_S = 60.0


async def discover_brokered_tools(
    command: str,
    args: Sequence[str],
    env: Mapping[str, str] | None = None,
) -> tuple[str, ...]:
    """Return the bare tool names the brokered server actually lists.

    Sorted, because the surface built from this must not depend on the order a
    transport happened to answer in (NFR-002).
    """
    try:
        from mcp import ClientSession
        from mcp.client.stdio import StdioServerParameters, stdio_client
    except ImportError as exc:  # pragma: no cover -- exercised by the extra being absent
        raise RuntimeError(_MISSING_SDK) from exc

    parameters = StdioServerParameters(
        command=command,
        args=list(args),
        env=None if env is None else dict(env),
    )
    async with (
        stdio_client(parameters) as (read_stream, write_stream),
        ClientSession(read_stream, write_stream) as session,
    ):
        await session.initialize()
        listing = await session.list_tools()
    return tuple(sorted(tool.name for tool in listing.tools))


async def discover_session(
    server_name: str,
    command: str,
    args: Sequence[str],
    env: Mapping[str, str] | None = None,
    cwd: Path | None = None,
) -> SessionSpec:
    """Build the session surface from a live listing by the broker itself.

    The returned spec is the whole surface. Nothing downstream adds to it, and
    :class:`~agentboundary.runner.session.SessionSpec` has no field through
    which a built-in tool could be added anyway.
    """
    brokered = await discover_brokered_tools(command, args, env)
    return session_spec(
        server_name=server_name,
        command=command,
        args=args,
        brokered_tools=brokered,
        cwd=cwd,
        env=env,
    )
