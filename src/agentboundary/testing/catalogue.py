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

from typing import Final

from agentboundary.model import Irreversibility, Tool
from agentboundary.registry import ToolRegistry

__all__ = ["MAX_PATH_ARGUMENT_LENGTH", "reference_registry"]

#: Longest path argument the schema accepts, in characters.
#:
#: 255, because that is the largest number the filesystem will honour whatever
#: shape the argument takes. It was 4096 -- the Linux ``PATH_MAX`` -- and the
#: generated benign corpus showed that promise could not be kept: an argument of
#: exactly 4096 characters passed validation and then failed to resolve with
#: ``ENAMETOOLONG``, because the resolved path is ``fs_root`` *plus* the
#: argument, and macOS caps a whole path at 1024. The guard refusing an
#: unresolvable path is right -- undecidable means refuse -- so the defect was
#: the schema, which declared a bound the layer beneath it never agreed to.
#:
#: Two ceilings apply, and 255 is under both for any root:
#:
#: - ``NAME_MAX`` is 255 on ext4, APFS, XFS and NTFS. The worst-case shape of a
#:   path argument is a single component, so a bound above 255 is refusable on
#:   spelling alone.
#: - ``PATH_MAX`` is 1024 on macOS and 4096 on Linux, and it bounds the
#:   *resolved* path. A schema cannot see the task's root, so it must leave room
#:   for one: 255 leaves at least 768 characters of root on the tighter of the
#:   two platforms this project is tested on.
#:
#: Not claimed for legacy Windows, where ``MAX_PATH`` is 260 for the whole path
#: and no argument bound worth having clears it. A deployment there sets its own
#: number; the point of this one is that it is derived rather than round.
#:
#: Verified by test rather than asserted here: ``tests/unit/test_confinement.py``
#: submits a path of exactly this length, as one component and as several, and
#: fails if the filesystem under CI will not resolve it.
MAX_PATH_ARGUMENT_LENGTH: Final[int] = 255

_PATH_SCHEMA = {
    "type": "object",
    "properties": {
        "path": {"type": "string", "minLength": 1, "maxLength": MAX_PATH_ARGUMENT_LENGTH}
    },
    "required": ["path"],
}

_WRITE_SCHEMA = {
    "type": "object",
    "properties": {
        "path": {"type": "string", "minLength": 1, "maxLength": MAX_PATH_ARGUMENT_LENGTH},
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
