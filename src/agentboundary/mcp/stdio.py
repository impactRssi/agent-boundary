"""Thin MCP stdio adapter over :class:`BrokeredServer`.

Deliberately thin. Every authorisation decision has already happened in
``BrokeredServer``; this module only translates between MCP's message shapes
and that class. Keeping it thin is what stops a second transport from acquiring
a second, weaker authorisation path -- the failure mode where the HTTP variant
of a service quietly skips a check the stdio one performs.

Thin is not the same as unexercised. Until node N-30 this module sat at 0%
coverage and no test imported it, which is how it came to be written against an
SDK API that no longer exists: the decorator form (``@app.list_tools()``) was
removed in MCP SDK 2.0 in favour of constructor handlers, and the adapter would
have raised ``AttributeError`` on the first call. ``tests/e2e/test_stdio_transport.py``
now drives it as a real subprocess over a real pipe, so the next such drift
fails the build instead of the operator's first run.

Requires the ``mcp`` extra::

    pip install "agent-boundary[mcp]"
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:  # pragma: no cover -- import-time typing only
    from agentboundary.mcp.server import BrokeredServer

__all__ = ["REFUSAL_PREFIX", "run_stdio"]

_MISSING_SDK = (
    "The MCP stdio transport needs the optional 'mcp' extra:\n"
    '    pip install "agent-boundary[mcp]"\n'
    "The core package carries zero runtime dependencies by design (ADR-0005)."
)

#: Leads the text of every refusal that crosses the wire. A fixed, greppable
#: token so an operator scanning a transcript can find refusals without knowing
#: the reason vocabulary, and so a client that only ever sees prose can still
#: tell "refused" from "returned nothing".
REFUSAL_PREFIX = "REFUSED"


def _refusal_text(reason: str | None, detail: str) -> str:
    return (
        f"{REFUSAL_PREFIX} [{reason}] {detail}\n"
        f"This call was not performed. The refusal is final for these "
        f"arguments; retrying them will produce the same result."
    )


async def run_stdio(server: BrokeredServer, name: str = "agent-boundary") -> None:
    """Serve one brokered task over MCP stdio.

    Refusals cross the wire as tool errors carrying the machine-readable
    refusal reason. They are not exceptions and not empty results: an agent
    that cannot tell 'refused' from 'returned nothing' will retry forever, and
    an operator reading the transcript needs the reason string.

    The reason is carried twice on purpose -- once in ``structured_content``
    for a caller that parses, once in the text for a caller that only reads.
    A refusal legible to exactly one of the two is a refusal half the callers
    will treat as a transport hiccup and retry.
    """
    try:
        import mcp.server.stdio
        from mcp.server import Server
        from mcp.types import CallToolResult, ListToolsResult, TextContent
        from mcp.types import Tool as MCPTool
    except ImportError as exc:  # pragma: no cover -- exercised by the extra being absent
        raise RuntimeError(_MISSING_SDK) from exc

    async def _on_list_tools(context: Any, params: Any) -> Any:
        """Exactly the task's scope. An out-of-scope tool is absent, not hidden."""
        del context, params
        return ListToolsResult(
            tools=[
                MCPTool(
                    name=entry["name"],
                    description=entry["description"],
                    input_schema=entry["input_schema"] or {"type": "object", "properties": {}},
                )
                for entry in server.list_tools()
            ]
        )

    async def _on_call_tool(context: Any, params: Any) -> Any:
        del context
        outcome = server.call_tool(params.name, params.arguments or {})
        if not outcome.authorised:
            return CallToolResult(
                content=[
                    TextContent(
                        type="text", text=_refusal_text(outcome.refusal_reason, outcome.detail)
                    )
                ],
                structured_content={
                    "refused": True,
                    "reason": outcome.refusal_reason,
                    "detail": outcome.detail,
                },
                # A tool error, not a protocol error. A JSON-RPC error would be
                # indistinguishable to many clients from the server being
                # unreachable, and "unreachable" is a condition agents retry.
                is_error=True,
            )
        assert outcome.envelope is not None  # noqa: S101 -- authorised implies an envelope
        return CallToolResult(
            content=[TextContent(type="text", text=outcome.envelope.render())],
            is_error=False,
        )

    # Handlers are passed at construction rather than registered afterwards, so
    # a server object cannot exist in a state where `tools/call` is served by
    # something other than the broker.
    app: Any = Server(name, on_list_tools=_on_list_tools, on_call_tool=_on_call_tool)

    async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
        await app.run(read_stream, write_stream, app.create_initialization_options())
