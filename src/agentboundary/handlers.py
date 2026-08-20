"""Reference tool handlers for the catalogue in ``agentboundary.testing.catalogue``.

These do the real thing: read and write real files, make real HTTP requests.
They are safe to ship because of what they *do not* do -- no handler re-checks
scope, confinement, egress, budget, or approval. By the time a handler runs,
the broker has already decided, and a handler that defended itself would be
saying the guard was advisory.

The one thing a handler must still do is resolve its own paths relative to the
task root, since the broker validates the argument but does not rewrite it.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Final

__all__ = ["HandlerError", "filesystem_handlers", "http_handlers"]

#: Response bytes read from a permitted host. Bounded because a permitted host
#: returning an unbounded stream is a denial-of-service and a context-overflow
#: carrier at the same time; ingest truncates too, but not before the bytes
#: have already been read into this process.
_MAX_RESPONSE_BYTES: Final[int] = 5_000_000

_TIMEOUT_S: Final[float] = 10.0

#: urlopen will open file:/ and ftp:/ as readily as http. See _request.
_PERMITTED_SCHEMES: Final[frozenset[str]] = frozenset({"http", "https"})


class HandlerError(Exception):
    """A handler could not complete. Not a refusal -- the broker authorised."""


def filesystem_handlers(root: Path) -> dict[str, Any]:
    """Read and write inside ``root``.

    ``root`` is the task's ``fs_root``. The broker has already proven every
    path argument resolves inside it, so these join and go.
    """

    def fs_read(arguments: Mapping[str, Any]) -> str:
        target = root / str(arguments["path"])
        try:
            return target.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            msg = f"could not read {arguments['path']!r}: {exc}"
            raise HandlerError(msg) from exc

    def fs_write(arguments: Mapping[str, Any]) -> str:
        target = root / str(arguments["path"])
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(str(arguments["content"]), encoding="utf-8")
        except OSError as exc:
            msg = f"could not write {arguments['path']!r}: {exc}"
            raise HandlerError(msg) from exc
        return f"wrote {len(str(arguments['content']))} bytes to {arguments['path']}"

    return {"fs.read": fs_read, "fs.write": fs_write}


def http_handlers() -> dict[str, Any]:
    """Fetch and post to hosts the broker has already allowlisted."""

    def _request(url: str, data: bytes | None = None) -> str:
        # The scheme is checked here as well as in EgressGuard, and that is not
        # a handler second-guessing its guard. The guard decides *which host*
        # this deployment permits; this decides whether urlopen is being asked
        # to do HTTP at all, because urlopen will just as happily open file:/
        # or ftp:/ -- a different capability class, not a different destination.
        # It also means these handlers stay safe if someone imports them
        # outside a broker, which is a thing people do with reference code.
        #
        # It is NOT a substitute for EgressGuard. Remove the guard and this
        # function will cheerfully fetch from anywhere on the internet.
        scheme = urllib.parse.urlsplit(url).scheme.lower()
        if scheme not in _PERMITTED_SCHEMES:
            msg = (
                f"refusing to open {url!r}: scheme {scheme!r} is not one of "
                f"{', '.join(sorted(_PERMITTED_SCHEMES))}"
            )
            raise HandlerError(msg)

        request = urllib.request.Request(  # noqa: S310
            url,
            data=data,
            method="POST" if data is not None else "GET",
            headers={"User-Agent": "agent-boundary/0.1"},
        )
        try:
            # nosec B310 / noqa: S310 -- B310 warns that urlopen accepts
            # file:/ and custom schemes. It does, which is why the scheme is
            # checked above against an http/https allowlist before we get here,
            # and why EgressGuard has already checked the host. Both scanners
            # flag the call shape and neither can see either check. Reviewed
            # and accepted; the suppression is per-call, not a rule-wide
            # disable, so a new urlopen elsewhere still fails the gate.
            with urllib.request.urlopen(  # noqa: S310
                request, timeout=_TIMEOUT_S
            ) as response:  # nosec B310
                body = response.read(_MAX_RESPONSE_BYTES + 1)
        except urllib.error.URLError as exc:
            msg = f"request to {url!r} failed: {exc}"
            raise HandlerError(msg) from exc

        raw: bytes = body
        if len(raw) > _MAX_RESPONSE_BYTES:
            msg = (
                f"response from {url!r} exceeded {_MAX_RESPONSE_BYTES} bytes; "
                f"refusing to buffer an unbounded stream"
            )
            raise HandlerError(msg)
        return raw.decode("utf-8", errors="replace")

    def http_get(arguments: Mapping[str, Any]) -> str:
        return _request(str(arguments["url"]))

    def http_post(arguments: Mapping[str, Any]) -> str:
        return _request(str(arguments["url"]), str(arguments["body"]).encode("utf-8"))

    return {"http.get": http_get, "http.post": http_post}


def json_file_ticket_handlers(path: Path) -> dict[str, Any]:
    """Ticketing backed by a JSON file, so the reference deployment is runnable.

    A real deployment substitutes its own. This exists so the worked example
    and the E2E tier exercise a ticketing shape without requiring an account.
    """

    def _load() -> list[dict[str, Any]]:
        if not path.exists():
            return []
        loaded: list[dict[str, Any]] = json.loads(path.read_text(encoding="utf-8"))
        return loaded

    def tickets_list(arguments: Mapping[str, Any]) -> str:
        del arguments
        return json.dumps([{"id": ticket["id"]} for ticket in _load()])

    def tickets_get(arguments: Mapping[str, Any]) -> str:
        wanted = int(arguments["ticket_id"])
        for ticket in _load():
            if ticket["id"] == wanted:
                return json.dumps(ticket)
        msg = f"ticket {wanted} not found"
        raise HandlerError(msg)

    def tickets_comment(arguments: Mapping[str, Any]) -> str:
        return f"commented on ticket {arguments['ticket_id']}"

    def tickets_delete(arguments: Mapping[str, Any]) -> str:
        wanted = int(arguments["ticket_id"])
        remaining = [ticket for ticket in _load() if ticket["id"] != wanted]
        path.write_text(json.dumps(remaining), encoding="utf-8")
        return f"deleted ticket {wanted}"

    return {
        "tickets.list": tickets_list,
        "tickets.get": tickets_get,
        "tickets.comment": tickets_comment,
        "tickets.delete": tickets_delete,
    }
