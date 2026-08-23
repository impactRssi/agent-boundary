"""Read-only audit-trace and lease viewer -- nodes N-21 and N-45.

Attribution that exists only as JSON Lines on disk is attribution nobody uses
during an incident. This is how the trace is consumed.

The controlling property is what the server does **not** implement. There is no
PUT, no POST, no PATCH, no DELETE -- not guarded versions returning 403, but no
route at all. A viewer that could edit a trace would make the trace something
an operator has to trust rather than something they can rely on (FR-022).

**Leases are shown here for the same reason the trace is** (N-45): an operator
who cannot see what is currently granted cannot revoke it, and a lease nobody
can see is an unbounded one in every way that matters until it happens to
expire. The rule the trace already follows applies unchanged -- the page
displays and does not act. There is no grant control, no extend control and no
revoke control, because a viewer that could mint a lease would be a second write
path into the store, reachable over HTTP, in a process the whole design keeps
read-only. Revocation is an operator deleting a line from a file.

Serves on localhost, with no authentication, and says so: a trace carries
validated arguments and belongs behind whatever the operator already uses.
"""

from __future__ import annotations

import json
import time
from collections.abc import Sequence
from functools import partial
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Final

from agentboundary.audit import AuditRecord
from agentboundary.leases import Lease
from agentboundary.rotation import RotationAdvice

__all__ = ["ViewerHandler", "lease_payload", "serve", "trace_payload"]

_STATIC = Path(__file__).parent / "static"

_DAY_S: Final[float] = 86_400.0

#: Rendered above the leases. A lease is the one mechanism in this system that
#: makes an invariant hold less than it did, so the cost is stated where what it
#: bought is displayed -- not in a document the reader might find later.
LEASE_NOTICE: Final[str] = (
    "While a lease is in force, the invariant it widens does not hold for its subject. "
    "This page displays leases and cannot create, extend or revoke one: leases are "
    "granted out of band with `agent-boundary lease grant`, one at a time, with the "
    "subject typed out. To revoke, delete the lease's line from the store."
)


def trace_payload(records: Sequence[AuditRecord]) -> dict[str, Any]:
    """The JSON the page renders.

    Summary counts are computed here rather than in the browser so the figures
    an operator reads come from the same code path in every client, and so a
    rendering bug cannot quietly change a count.
    """
    entries = [record.to_json() for record in records]
    refused = [entry for entry in entries if entry["outcome"] == "refuse"]
    reasons: dict[str, int] = {}
    for entry in refused:
        reason = entry["reason"] or "unknown"
        reasons[reason] = reasons.get(reason, 0) + 1
    return {
        "records": entries,
        "summary": {
            "total": len(entries),
            "authorised": len(entries) - len(refused),
            "refused": len(refused),
            "reasons": dict(sorted(reasons.items())),
        },
    }


def _state(lease: Lease, now: float) -> str:
    """``active``, ``pending`` or ``expired``, from the type's own predicate.

    :meth:`agentboundary.leases.Lease.is_active` is the half-open check the
    guards use. Asking it, rather than comparing timestamps again here, is what
    stops the page saying "active" about a lease the broker has already stopped
    honouring -- the one disagreement an operator would have no way to detect.
    """
    if lease.is_active(now):
        return "active"
    return "pending" if now < lease.granted_at else "expired"


def _state_text(lease: Lease, now: float) -> str:
    """The phrase the page prints. Rendered here so every client reads one figure.

    Same reasoning as the summary counts: a number formatted in the browser is a
    number a rendering bug can quietly change, and "1.9 days remaining" is the
    figure an operator decides on.
    """
    state = _state(lease, now)
    if state == "active":
        return f"active, {(lease.expires_at - now) / _DAY_S:.2f} days remaining"
    if state == "pending":
        return f"not yet in force, starts in {(lease.granted_at - now) / _DAY_S:.2f} days"
    return f"expired {(now - lease.expires_at) / _DAY_S:.2f} days ago"


def lease_payload(
    leases: Sequence[Lease],
    advisories: Sequence[RotationAdvice],
    now: float,
) -> dict[str, Any]:
    """What is granted, what has lapsed, and what rotation that owes.

    Expired leases are included rather than filtered out, because "no lease was
    ever granted" and "a lease expired" are different states and the second is
    what a rotation advisory is made of.
    """
    rows = [
        {
            **lease.to_json(),
            "state": _state(lease, now),
            "state_text": _state_text(lease, now),
            "remaining_s": lease.expires_at - now,
            "digest": lease.digest,
        }
        for lease in sorted(leases, key=lambda item: (str(item.kind), item.subject))
    ]
    return {
        "now": now,
        "notice": LEASE_NOTICE,
        "leases": rows,
        "advisories": [advice.to_json() for advice in advisories],
        "summary": {
            "granted": len(rows),
            "active": sum(1 for row in rows if row["state"] == "active"),
            "expired": sum(1 for row in rows if row["state"] == "expired"),
            "rotation_owed": len(advisories),
        },
    }


class ViewerHandler(BaseHTTPRequestHandler):
    """Serves the page, the trace and the leases. GET and HEAD only.

    ``BaseHTTPRequestHandler`` answers any method it has no ``do_<METHOD>`` for
    with 501, so omitting them is sufficient -- and is a stronger statement than
    writing handlers that refuse.
    """

    server_version = "agent-boundary-viewer"
    sys_version = ""

    records: Sequence[AuditRecord] = ()
    leases: Sequence[Lease] = ()
    advisories: Sequence[RotationAdvice] = ()

    #: Pin the instant "time remaining" is measured against. ``None`` means the
    #: wall clock, which is what an operator wants; a test pins it so the figure
    #: on the page is deterministic. A float rather than a callable on purpose:
    #: a function stored as a class attribute becomes a bound method on access,
    #: and would silently be handed ``self``.
    pinned_now: float | None = None

    # Method names are fixed by BaseHTTPRequestHandler's dispatch.
    def do_GET(self) -> None:
        route = self.path.split("?", 1)[0]
        if route in {"/", "/index.html"}:
            self._send(
                HTTPStatus.OK, "text/html; charset=utf-8", (_STATIC / "index.html").read_bytes()
            )
        elif route == "/trace.json":
            body = json.dumps(trace_payload(self.records), ensure_ascii=False).encode("utf-8")
            self._send(HTTPStatus.OK, "application/json; charset=utf-8", body)
        elif route == "/leases.json":
            now = time.time() if self.pinned_now is None else self.pinned_now
            payload = lease_payload(self.leases, self.advisories, now)
            body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            self._send(HTTPStatus.OK, "application/json; charset=utf-8", body)
        else:
            self._send(HTTPStatus.NOT_FOUND, "text/plain; charset=utf-8", b"not found\n")

    def do_HEAD(self) -> None:
        self._send(HTTPStatus.OK, "text/html; charset=utf-8", b"", body_in_response=False)

    def _send(
        self, status: HTTPStatus, content_type: str, body: bytes, *, body_in_response: bool = True
    ) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        # The page is entirely self-contained; nothing it renders should be
        # able to reach the network. A trace is full of attacker-authored
        # strings, so a payload that got a URL rendered must not be able to
        # turn that into a request.
        self.send_header(
            "Content-Security-Policy",
            "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; "
            "connect-src 'self'",
        )
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.end_headers()
        if body_in_response and body:
            self.wfile.write(body)

    def log_message(self, format: str, *args: Any) -> None:
        """Silence the default stderr access log; it is noise in a CLI tool."""


def serve(
    records: Sequence[AuditRecord],
    host: str = "127.0.0.1",
    port: int = 8765,
    leases: Sequence[Lease] = (),
    advisories: Sequence[RotationAdvice] = (),
) -> None:
    """Serve a trace and the leases in force, until interrupted.

    Localhost by default, deliberately. ``leases`` and ``advisories`` are values,
    read once by the caller: this server holds no store handle, so it cannot
    re-read one and certainly cannot write one.
    """
    handler = partial(_bound_handler, tuple(records), tuple(leases), tuple(advisories))
    with ThreadingHTTPServer((host, port), handler) as httpd:
        bound_port = httpd.server_address[1]
        print(f"audit viewer on http://{host}:{bound_port}  (read-only, no auth)")
        httpd.serve_forever()


def _bound_handler(
    records: Sequence[AuditRecord],
    leases: Sequence[Lease],
    advisories: Sequence[RotationAdvice],
    *args: Any,
    **kwargs: Any,
) -> ViewerHandler:
    handler_class = type(
        "BoundViewerHandler",
        (ViewerHandler,),
        {"records": records, "leases": leases, "advisories": advisories},
    )
    instance: ViewerHandler = handler_class(*args, **kwargs)
    return instance
