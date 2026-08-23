"""A reference MCP server that puts the broker on the wire.

Why a server rather than a library. A broker imported as a library is one
import away from being bypassed: a developer who calls a tool handler directly
has removed the control and nothing in the diff says so. Behind a process
boundary the tools live *behind* the broker rather than beside it, and there is
no in-process path to them (ADR-0005).

Two properties carry across the transport, and both are tested:

* **The tool list is the task's scope.** ``list_tools`` returns exactly the
  tools the task construction admitted. An agent on the other end cannot name
  what is not listed, and naming it anyway resolves to nothing (I1).
* **Results are envelopes.** Every handler return value goes through ingest
  before it crosses back, so there is no path by which a raw tool result
  re-enters a model context (I2, FR-019).
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from agentboundary.approval import ApprovalGuard, ApprovalStore
from agentboundary.audit import AuditRecord, AuditSink, MemoryAuditSink, ResultStatus
from agentboundary.broker import Broker
from agentboundary.budget import BudgetGuard, BudgetLedger
from agentboundary.confinement import EgressGuard, PathConfinementGuard, assert_out_of_reach
from agentboundary.guards import Guard
from agentboundary.ingest import Envelope, ingest
from agentboundary.ledger import RefusalLedger, record_refusal
from agentboundary.model import ProposedCall, Task
from agentboundary.registry import ToolRegistry

__all__ = ["BrokeredServer", "ToolHandler", "build_server"]

#: A handler receives the **validated** arguments and returns a raw result.
#: The raw result never reaches the agent: BrokeredServer wraps it in an
#: envelope before it crosses the wire.
ToolHandler = Callable[[Mapping[str, Any]], Any]


@dataclass(frozen=True, slots=True)
class CallOutcome:
    """What happened, in a form both the wire and the audit trace can carry."""

    authorised: bool
    envelope: Envelope | None
    refusal_reason: str | None
    detail: str


class BrokeredServer:
    """Wraps a task, a broker, and a set of handlers behind one entry point.

    Deliberately transport-agnostic. The MCP wiring in :func:`build_server` is
    thin on top of this, so the invariants can be tested without standing up a
    protocol -- and so a second transport cannot quietly acquire a second,
    weaker authorisation path.
    """

    __slots__ = ("_audit", "_broker", "_handlers", "_refusals", "_sequence")

    def __init__(
        self,
        broker: Broker,
        handlers: Mapping[str, ToolHandler],
        audit: AuditSink | None = None,
        refusals: RefusalLedger | None = None,
    ) -> None:
        missing = sorted(set(broker.scoped_tools.names()) - set(handlers))
        if missing:
            # A scoped tool with no handler would authorise and then fail at
            # dispatch, which reads to an operator as a broker fault. Fail at
            # construction instead, where the configuration error actually is.
            msg = f"task {broker.task.id!r} scopes tool(s) with no handler: {', '.join(missing)}"
            raise ValueError(msg)
        self._broker = broker
        self._handlers = dict(handlers)
        # `is None`, not `or`. MemoryAuditSink defines __len__, so an empty
        # sink is falsy and `audit or ...` silently discarded the caller's
        # sink -- sending the whole trace to a throwaway. An audit trace that
        # quietly goes nowhere is the worst possible instance of this bug.
        self._audit = audit if audit is not None else MemoryAuditSink()
        # Optional, and `None` means "no ledger" rather than "a throwaway one".
        # A refusal ledger is an operator artifact: silently substituting an
        # in-process one would report an empty ledger to whoever went looking.
        if refusals is not None:
            _assert_ledger_out_of_reach(refusals, broker.task)
        self._refusals = refusals
        self._sequence = 0

    @property
    def audit(self) -> AuditSink:
        return self._audit

    @property
    def refusals(self) -> RefusalLedger | None:
        return self._refusals

    @property
    def task(self) -> Task:
        return self._broker.task

    def list_tools(self) -> list[dict[str, Any]]:
        """Exactly the task's scope. Nothing the deployment merely supports."""
        return self._broker.scoped_tools.model_schema()

    def call_tool(self, name: str, arguments: Mapping[str, Any]) -> CallOutcome:
        """Authorise, then dispatch, then wrap. Never dispatch before authorising."""
        proposed = ProposedCall(tool_name=name, arguments=dict(arguments))
        decision = self._broker.authorise(proposed)
        self._sequence += 1

        if not decision.authorised:
            self._audit.append(
                AuditRecord.from_decision(self.task, proposed, decision, self._sequence)
            )
            if self._refusals is not None:
                # Recorded, and that is all. Nothing downstream of this call
                # can turn the entry into permission -- see the trap described
                # in agentboundary.ledger.
                record_refusal(self._refusals, self.task, proposed, decision)
            reason = str(decision.reason) if decision.reason else None
            return CallOutcome(
                authorised=False,
                envelope=None,
                refusal_reason=reason,
                detail=decision.checks[-1].detail if decision.checks else "",
            )

        # Dispatch on the *resolved* tool's canonical name, not on the string
        # the agent sent. They differ whenever the proposal used a
        # compatibility form, and dispatching on the raw name would miss the
        # handler for a call the broker just authorised.
        resolved = self._broker.scoped_tools.get(name)
        assert resolved is not None  # noqa: S101 -- authorisation implies resolution
        handler = self._handlers[resolved.name]
        try:
            raw = handler(decision.validated_arguments)
            status = ResultStatus.SUCCEEDED
            detail = ""
        except Exception as exc:
            # The handler failed. That is not a refusal -- the broker did
            # authorise -- so it is recorded as a failed effect, not as a
            # refusal the operator would then look for a control behind.
            raw = None
            status = ResultStatus.FAILED
            detail = f"{type(exc).__name__}: {exc}"

        self._audit.append(
            AuditRecord.from_decision(
                self.task, proposed, decision, self._sequence, result_status=status
            )
        )

        # Even a handler's own error text is untrusted: a third-party API's
        # error string is an attacker-writable carrier (threat model §2).
        envelope = ingest(
            raw if status == ResultStatus.SUCCEEDED else detail,
            tool_name=name,
            source=f"task:{self.task.id}",
            provenance={"result_status": status},
        )
        return CallOutcome(authorised=True, envelope=envelope, refusal_reason=None, detail=detail)


def build_broker(
    task: Task,
    registry: ToolRegistry,
    approvals: ApprovalStore | None = None,
    ledger: BudgetLedger | None = None,
) -> Broker:
    """Assemble the standard guard pipeline for a task.

    One place, so a deployment cannot accidentally stand up a broker missing a
    guard. Adding a guard here reaches every transport at once.
    """
    guards: list[Guard] = [
        PathConfinementGuard(),
        EgressGuard(),
        BudgetGuard(ledger if ledger is not None else BudgetLedger(task.caps)),
        ApprovalGuard(approvals if approvals is not None else ApprovalStore()),
    ]
    return Broker(task, registry.scope_for(task), guards)


def _assert_ledger_out_of_reach(refusals: RefusalLedger, task: Task) -> None:
    """Refuse to attach a ledger the task's own tools could write.

    Checked by asking the ledger where it lives rather than by testing its
    concrete type, so a deployment's own file-backed implementation is held to
    the same rule as :class:`~agentboundary.ledger.FileRefusalLedger`. A ledger
    that keeps nothing on disk exposes no ``path`` and has nothing to check.
    """
    location = getattr(refusals, "path", None)
    if isinstance(location, Path):
        assert_out_of_reach(location, task.fs_root, "refusal ledger")


def build_server(
    task: Task,
    registry: ToolRegistry,
    handlers: Mapping[str, ToolHandler],
    approvals: ApprovalStore | None = None,
    audit: AuditSink | None = None,
    refusals: RefusalLedger | None = None,
) -> BrokeredServer:
    """Build a brokered server for one task."""
    return BrokeredServer(build_broker(task, registry, approvals), handlers, audit, refusals)
