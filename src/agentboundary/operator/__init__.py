"""The operator interface -- N-45. Out of band, and structurally so.

An operator sees that the broker refused something, decides whether that
refusal was legitimate, and -- if it was not -- grants a bounded lease. This
package is where that happens, and it is a **separate program** from the
broker, not a mode of it.

**Why a package and not a module.** The trap Phase 9 is designed against is a
refusal ledger that feeds a grant workflow (A3, A9). The defence is that no
single scope ever holds both a refusal record and a lease constructor:

* :mod:`agentboundary.operator.refusals` imports the ledger and nothing from
  the lease modules.
* :mod:`agentboundary.operator.grant` and
  :mod:`agentboundary.operator.listing` import the lease modules and nothing
  from the ledger.
* :mod:`agentboundary.operator.cli` imports **neither** at module level. Each
  command's implementation is imported inside the branch that runs it, so the
  dispatcher has no name for either.

The consequence is that "promote this ledger row into a lease" cannot be
written as a local change. It needs a new import edge, in a module that has a
test asserting the edge is absent. See ``tests/unit/test_operator_cli.py``.

**Why the broker never imports this package.** :mod:`agentboundary.operator.grant`
holds the only code in the project that writes a lease file.
:class:`~agentboundary.leases.LeaseStore` deliberately has no ``grant``, for the
same reason :class:`~agentboundary.approval.ApprovalStore` has none: if the
broker could mint a lease, anything reachable from a steered agent loop could
mint one too. Keeping the write path in a package the serving process never
imports makes that a property of the process image rather than of a convention
-- ``tests/e2e/test_operator_interface.py`` asserts it by inspecting
``sys.modules`` in a real serving subprocess.
"""

from __future__ import annotations

from agentboundary.operator.cli import build_parser, main

__all__ = ["build_parser", "main"]
