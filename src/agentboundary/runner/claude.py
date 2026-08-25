"""Thin binding from a :class:`SessionSpec` to the Claude Agent SDK (N-50).

Deliberately thin, for the reason :mod:`agentboundary.mcp.stdio` gives about
transports: every decision about what this session may reach has already been
taken in :mod:`agentboundary.runner.session`, and a binding that decided
anything itself would be a second place the surface is determined.

Thin is not the same as unexercised. ``stdio.py`` sat at 0% coverage long
enough to drift against an SDK API that had been removed, and would have raised
``AttributeError`` on an operator's first call. So
``tests/e2e/test_broker_only_runner.py`` constructs the real
``ClaudeAgentOptions`` from a real spec and asserts the fields that carry the
property. Constructing options -- and constructing the client -- runs no model
and opens no socket; only entering the client's context does, and no test does
that.

What is **not** verified anywhere in this repository: that the runtime behind
the SDK honours ``tools=[]``. That is an upstream guarantee, stated in the
SDK's own documentation for the option, and this repository takes it on trust
the same way it takes the operating system's process isolation on trust. What
is verified here is that the option is set, set to the empty list rather than
left to a default, and that nothing in the surface names a native handle.

Requires the ``runner`` extra::

    pip install "agent-boundary[runner]"
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any

from agentboundary.runner.session import SessionSpec

__all__ = ["run_session", "session_client", "session_options"]

_MISSING_SDK = (
    "The brokered runner needs the optional 'runner' extra:\n"
    '    pip install "agent-boundary[runner]"\n'
    "The core package carries zero runtime dependencies by design (ADR-0005), "
    "and an agent SDK never enters the authorisation path (ADR-0009 §6)."
)


def session_options(spec: SessionSpec) -> Any:
    """Translate a session surface into the SDK's options object.

    One call, no logic. Every value comes from
    :meth:`SessionSpec.sdk_options`, which is plain data precisely so that the
    values can be asserted without this import succeeding.

    Passing the mapping through ``**`` rather than naming each field is what
    makes SDK drift loud: a renamed or removed option raises ``TypeError`` at
    construction, in a test, instead of being silently dropped into a session
    that then runs with a default surface.
    """
    try:
        from claude_agent_sdk import ClaudeAgentOptions
    except ImportError as exc:  # pragma: no cover -- exercised by the extra being absent
        raise RuntimeError(_MISSING_SDK) from exc
    return ClaudeAgentOptions(**spec.sdk_options())


def session_client(spec: SessionSpec) -> Any:
    """A client for one brokered session, not yet connected.

    Construction spawns nothing. The caller enters it as an async context
    manager, and that is the first moment anything leaves this machine.
    """
    try:
        from claude_agent_sdk import ClaudeSDKClient
    except ImportError as exc:  # pragma: no cover -- exercised by the extra being absent
        raise RuntimeError(_MISSING_SDK) from exc
    return ClaudeSDKClient(options=session_options(spec))


async def run_session(spec: SessionSpec, prompt: str) -> AsyncIterator[Any]:
    """Run one prompt in a session whose only tools are the broker's.

    **This calls a model and needs the network**, so nothing in the test suite
    reaches it -- see ``ADR-0009``, which separates reproducible offline
    measurement from model-in-the-loop evidence and forbids the second from
    gating a build. The offline half of this module is
    :func:`session_options`, and that is what the tests drive.

    Yields the SDK's messages unchanged. Interpreting them is the caller's
    problem, and deliberately so: an agent's own narration of what it did is
    the least trustworthy record of what it did. The trustworthy record is the
    broker's audit trace, written by the broker process on the far side of the
    transport.
    """
    client = session_client(spec)
    async with client:
        await client.query(prompt)
        async for message in client.receive_response():
            yield message
