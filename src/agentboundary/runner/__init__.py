"""A runner whose only tools are the broker's -- the reference integration (N-50).

I1 says the model cannot reach a tool outside the task's allowlist. That is a
property of the *broker*, and on its own it says nothing about the session the
broker is plugged into. A harness that routes some calls through a broker while
a native ``Bash`` handle stays open in the same session has demonstrated
nothing, because the effect the broker refused was reachable by another route.
This package closes that route by construction, which is ``ADR-0002``'s
argument applied to this repository rather than to its users.

Three modules, split along the dependency line ``ADR-0009`` §6 draws:

* :mod:`agentboundary.runner.session` -- where the surface is decided. Standard
  library only, and held there by the guard in
  ``tests/unit/test_evidence_is_not_a_benchmark.py``.
* :mod:`agentboundary.runner.discovery` -- asks the broker what it serves, over
  a real MCP transport to a real child process. Needs the MCP SDK.
* :mod:`agentboundary.runner.claude` -- hands the surface to the agent SDK.
  Needs the agent SDK.

Optional import throughout. The core package carries zero runtime dependencies;
the two SDKs arrive only with the ``runner`` extra::

    pip install "agent-boundary[runner]"

Nothing in this package is on the authorisation path. It decides what the
session can *name*; the broker, in its own process, decides what happens when
the session names it. Both are needed, and neither substitutes for the other.
"""

from agentboundary.runner.session import (
    MCP_QUALIFIER,
    NATIVE_TOOL_FAMILIES,
    NO_BUILTIN_TOOLS,
    BrokeredServerSpec,
    SessionSpec,
    SessionSurfaceError,
    qualify,
    session_spec,
)

__all__ = [
    "MCP_QUALIFIER",
    "NATIVE_TOOL_FAMILIES",
    "NO_BUILTIN_TOOLS",
    "BrokeredServerSpec",
    "SessionSpec",
    "SessionSurfaceError",
    "qualify",
    "session_spec",
]
