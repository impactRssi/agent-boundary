"""``agent-boundary refusals`` -- read the ledger, and read it as evidence.

This module imports :mod:`agentboundary.ledger` and imports nothing from
:mod:`agentboundary.leases`, :mod:`agentboundary.operator.grant`, or
:mod:`agentboundary.operator.listing`. It has no way to name a lease, so no
patch to this file alone can turn a row it printed into a grant. The absence is
asserted by ``tests/unit/test_operator_cli.py``.

Two consequences follow, and they are the whole reason the command is shaped
the way it is.

**Nothing here is numbered, keyed, or selectable.** The output has no row
index, no identifier, and no handle of any sort. ``lease grant`` requires its
subject to be typed out, and there is deliberately nothing on this screen to
copy but the subject itself -- because the moment a row has a number, "grant 3"
is the obvious next feature and bulk approval is one keystroke after that.

**The caveat travels with the rows, in every format.** A ledger entry cannot
distinguish a legitimate workflow from a payload that steered the agent: both
produce the same row, and a high count is what a retry loop induced by injected
content looks like. :data:`agentboundary.ledger.CAVEAT` says so, and the JSON
form carries it too -- a caveat that only the human-readable output shows is a
caveat that disappears the first time someone pipes the command into a
dashboard.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import TextIO

from agentboundary.ledger import CAVEAT, FileRefusalLedger, render

__all__ = ["run_refusals"]


def run_refusals(ledger_path: Path, stream: TextIO, *, as_json: bool = False) -> int:
    """Print the aggregated ledger. Returns a process exit code.

    A path that does not exist is an **error**, not an empty ledger. The two are
    indistinguishable in the output -- both would print "No refusals recorded."
    -- and the wrong one is the dangerous reading: an operator who mistyped the
    path would conclude the broker has refused nothing, which is exactly the
    state a deployment with a broken ledger is in.
    """
    if not ledger_path.exists():
        print(
            f"error: no refusal ledger at {ledger_path}. Refusing to report an empty "
            f"ledger for a path that does not exist -- 'nothing was refused' and "
            f"'nothing was recorded' are different states and must not print the same.",
            file=stream,
        )
        return 2

    ledger = FileRefusalLedger(ledger_path)
    entries = ledger.entries()

    if as_json:
        payload = {
            "caveat": CAVEAT,
            "source": str(ledger_path),
            "entries": [entry.to_json() for entry in entries],
        }
        print(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True), file=stream)
        return 0

    print(render(entries), file=stream)
    if entries:
        print(
            "\nTo widen scope, run `agent-boundary lease grant` and type the subject out. "
            "There is no way to grant from this list: it carries no row numbers and no "
            "identifiers, on purpose.",
            file=stream,
        )
    return 0
