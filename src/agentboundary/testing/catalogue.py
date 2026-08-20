"""A reference tool catalogue, shared by the corpus and the worked example.

Not a toy. These are the shapes real deployments wire up -- a filesystem, an
HTTP client, a ticketing API -- and the point of fixing them here is that every
corpus payload attacks the *same* deployment. A corpus where each payload
invents its own convenient tool set proves nothing about a coherent system.

Irreversibility classes are set explicitly and conservatively. Anything that
writes, deletes, or leaves the process is ``IRREVERSIBLE`` unless it has a
tested undo.
"""

from __future__ import annotations

from agentboundary.model import Irreversibility, Tool
from agentboundary.registry import ToolRegistry

__all__ = ["reference_registry"]

_PATH_SCHEMA = {
    "type": "object",
    "properties": {"path": {"type": "string", "minLength": 1, "maxLength": 4096}},
    "required": ["path"],
}

_WRITE_SCHEMA = {
    "type": "object",
    "properties": {
        "path": {"type": "string", "minLength": 1, "maxLength": 4096},
        "content": {"type": "string", "maxLength": 1_000_000},
    },
    "required": ["path", "content"],
}

_URL_SCHEMA = {
    "type": "object",
    "properties": {"url": {"type": "string", "minLength": 1, "maxLength": 2048}},
    "required": ["url"],
}

_POST_SCHEMA = {
    "type": "object",
    "properties": {
        "url": {"type": "string", "minLength": 1, "maxLength": 2048},
        "body": {"type": "string", "maxLength": 100_000},
    },
    "required": ["url", "body"],
}

_TICKET_ID_SCHEMA = {
    "type": "object",
    "properties": {"ticket_id": {"type": "integer", "minimum": 1}},
    "required": ["ticket_id"],
}

_COMMENT_SCHEMA = {
    "type": "object",
    "properties": {
        "ticket_id": {"type": "integer", "minimum": 1},
        "body": {"type": "string", "minLength": 1, "maxLength": 20_000},
    },
    "required": ["ticket_id", "body"],
}


def reference_registry() -> ToolRegistry:
    """The deployment catalogue every corpus payload is aimed at."""
    return ToolRegistry(
        [
            Tool(
                name="fs.read",
                arg_schema=_PATH_SCHEMA,
                irreversibility=Irreversibility.READ,
                cost_weight=1.0,
                description="Read a file inside the task's configured root.",
            ),
            Tool(
                name="fs.write",
                arg_schema=_WRITE_SCHEMA,
                irreversibility=Irreversibility.IRREVERSIBLE,
                cost_weight=1.0,
                description="Write a file inside the task's configured root.",
            ),
            Tool(
                name="http.get",
                arg_schema=_URL_SCHEMA,
                irreversibility=Irreversibility.READ,
                cost_weight=1.0,
                description="Fetch a URL from an allowlisted host.",
            ),
            Tool(
                name="http.post",
                arg_schema=_POST_SCHEMA,
                # Leaving the process is not undoable: once a body has been
                # sent to a third party, no local action retracts it.
                irreversibility=Irreversibility.IRREVERSIBLE,
                cost_weight=1.0,
                description="Send a body to an allowlisted host.",
            ),
            Tool(
                name="tickets.list",
                arg_schema={},
                irreversibility=Irreversibility.READ,
                cost_weight=1.0,
                description="List open tickets.",
            ),
            Tool(
                name="tickets.get",
                arg_schema=_TICKET_ID_SCHEMA,
                irreversibility=Irreversibility.READ,
                cost_weight=1.0,
                description="Read one ticket.",
            ),
            Tool(
                name="tickets.comment",
                arg_schema=_COMMENT_SCHEMA,
                # A comment can be deleted, but it has already been delivered
                # by notification. Publication is the irreversible part.
                irreversibility=Irreversibility.IRREVERSIBLE,
                cost_weight=1.0,
                description="Post a public comment on a ticket.",
            ),
            Tool(
                name="tickets.delete",
                arg_schema=_TICKET_ID_SCHEMA,
                irreversibility=Irreversibility.IRREVERSIBLE,
                cost_weight=1.0,
                description="Delete a ticket permanently.",
            ),
        ]
    )
