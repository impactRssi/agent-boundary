"""MCP integration -- the supported way to put the broker in front of an agent.

Optional import. The core package carries zero runtime dependencies (ADR-0005);
the MCP SDK arrives only with the ``mcp`` extra:

    pip install "agent-boundary[mcp]"
"""

from agentboundary.mcp.server import BrokeredServer, build_server

__all__ = ["BrokeredServer", "build_server"]
