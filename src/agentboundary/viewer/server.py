"""Read-only audit-trace viewer -- node N-21.

Attribution that exists only as JSON Lines on disk is attribution nobody uses
during an incident. This is how the trace is consumed.

The controlling property is what the server does **not** implement. There is no
PUT, no POST, no PATCH, no DELETE -- not guarded versions returning 403, but no
route at all. A viewer that could edit a trace would make the trace something
an operator has to trust rather than something they can rely on (FR-022).

Serves on localhost, with no authentication, and says so: a trace carries
validated arguments and belongs behind whatever the operator already uses.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from functools import partial
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from agentboundary.audit import AuditRecord

__all__ = ["ViewerHandler", "serve", "trace_payload"]

_STATIC = Path(__file__).parent / "static"


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


class ViewerHandler(BaseHTTPRequestHandler):
    """Serves the page and the trace. GET and HEAD only.

    ``BaseHTTPRequestHandler`` answers any method it has no ``do_<METHOD>`` for
    with 501, so omitting them is sufficient -- and is a stronger statement than
    writing handlers that refuse.
    """

    server_version = "agent-boundary-viewer"
    sys_version = ""

    records: Sequence[AuditRecord] = ()

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


def serve(records: Sequence[AuditRecord], host: str = "127.0.0.1", port: int = 8765) -> None:
    """Serve a trace until interrupted. Localhost by default, deliberately."""
    handler = partial(_bound_handler, tuple(records))
    with ThreadingHTTPServer((host, port), handler) as httpd:
        bound_port = httpd.server_address[1]
        print(f"audit viewer on http://{host}:{bound_port}  (read-only, no auth)")
        httpd.serve_forever()


def _bound_handler(records: Sequence[AuditRecord], *args: Any, **kwargs: Any) -> ViewerHandler:
    handler_class = type("BoundViewerHandler", (ViewerHandler,), {"records": records})
    instance: ViewerHandler = handler_class(*args, **kwargs)
    return instance
