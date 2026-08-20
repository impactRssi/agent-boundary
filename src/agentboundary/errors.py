"""Refusal reasons and broker exceptions.

Refusal reasons are **interface**, not diagnostics. An operator triaging an
incident acts on the reason string, so the set is closed, stable, and specified
in ``docs/SPEC.md`` §3. A reason that misreports why a call was refused is a
vulnerability under ``SECURITY.md``, not a cosmetic defect.
"""

from __future__ import annotations

from enum import Enum

__all__ = ["BrokerError", "RefusalReason", "TaskConstructionError"]


class RefusalReason(str, Enum):
    """Why the broker refused a call. Closed set -- see SPEC.md §3.

    Inheriting from ``str`` keeps the wire and audit representation stable: the
    JSON value is the reason string itself, not an integer that would silently
    remap if a member were ever reordered.
    """

    TOOL_NOT_IN_SCOPE = "tool_not_in_scope"
    TOOL_UNKNOWN = "tool_unknown"
    SCHEMA_INVALID = "schema_invalid"
    PATH_OUTSIDE_ROOT = "path_outside_root"
    EGRESS_HOST_NOT_ALLOWED = "egress_host_not_allowed"
    BUDGET_EXHAUSTED = "budget_exhausted"
    APPROVAL_REQUIRED = "approval_required"
    APPROVAL_EXPIRED = "approval_expired"
    APPROVAL_MISMATCH = "approval_mismatch"
    TASK_CONSTRUCTION_FAILED = "task_construction_failed"

    def __str__(self) -> str:
        return self.value


class BrokerError(Exception):
    """Base class for broker failures that are not ordinary refusals.

    A refusal is a normal, expected outcome carried in a ``Decision``. An
    exception here means the broker could not reach a decision at all, which is
    a different condition and must not be reported as a refusal.
    """


class TaskConstructionError(BrokerError):
    """A task could not be constructed, so it MUST NOT run.

    Raised rather than returned because there is no task to attribute a
    refusal to yet. Failing closed at construction is the point: a scope naming
    an unregistered tool must not silently narrow to the tools that do exist
    (FR-003).
    """
