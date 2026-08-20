"""Thin MCP stdio adapter over :class:`BrokeredServer`.

Deliberately thin. Every authorisation decision has already happened in
``BrokeredServer``; this module only translates between MCP's message shapes
and that class. Keeping it thin is what stops a second transport from acquiring
a second, weaker authorisation path -- the failure mode where the HTTP variant
of a service quietly skips a check the stdio one performs.

Requires the ``mcp`` extra::

    pip install "agent-boundary[mcp]"
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:  # pragma: no cover -- import-time typing only
    from agentboundary.mcp.server import BrokeredServer

__all__ = ["run_stdio"]

_MISSING_SDK = (
    "The MCP stdio transport needs the optional 'mcp' extra:\n"
    '    pip install "agent-boundary[mcp]"\n'
    "The core package carries zero runtime dependencies by design (ADR-0005)."
)


async def run_stdio(server: BrokeredServer, name: str = "agent-boundary") -> None:
    """Serve one brokered task over MCP stdio.

    Refusals cross the wire as tool errors carrying the machine-readable
    refusal reason. They are not exceptions and not empty results: an agent
    that cannot tell 'refused' from 'returned nothing' will retry forever, and
    an operator reading the transcript needs the reason string.
    """
    try:
        import mcp.server.stdio
        from mcp.server import Server
        from mcp.types import TextContent
        from mcp.types import Tool as MCPTool
    except ImportError as exc:  # pragma: no cover -- exercised by the extra being absent
        raise RuntimeError(_MISSING_SDK) from exc

    app: Any = Server(name)

    @app.list_tools()  # type: ignore[untyped-decorator]
    async def _list_tools() -> list[Any]:
        return [
            MCPTool(
                name=entry["name"],
                description=entry["description"],
                input_schema=entry["input_schema"] or {"type": "object", "properties": {}},
            )
            for entry in server.list_tools()
        ]

    @app.call_tool()  # type: ignore[untyped-decorator]
    async def _call_tool(name: str, arguments: dict[str, Any] | None) -> list[Any]:
        outcome = server.call_tool(name, arguments or {})
        if not outcome.authorised:
            return [
                TextContent(
                    type="text",
                    text=(
                        f"REFUSED [{outcome.refusal_reason}] {outcome.detail}\n"
                        f"This call was not performed. The refusal is final for these "
                        f"arguments; retrying them will produce the same result."
                    ),
                )
            ]
        assert outcome.envelope is not None  # noqa: S101 -- authorised implies an envelope
        return [TextContent(type="text", text=outcome.envelope.render())]

    async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
        await app.run(read_stream, write_stream, app.create_initialization_options())
