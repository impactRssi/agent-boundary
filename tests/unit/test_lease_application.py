"""Where a lease applies, and where it must not (N-43).

The near-miss table is the heart of this file. A path lease over ``/x/secrets``
must not admit ``/x/secrets-backup``, ``/x``, ``/x/secretsX``, or a traversal
out of the leased directory, and the reason it does not is that admission runs
through the same ``resolve_candidate`` + ``contains`` pair the task root runs
through. If someone ever replaces that with a prefix comparison, the sibling
case is the one that starts passing, so it is asserted first and by name.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from agentboundary.confinement import EgressGuard, PathConfinementGuard
from agentboundary.errors import RefusalReason, TaskConstructionError
from agentboundary.guards import CallContext
from agentboundary.leases import (
    InMemoryLeaseStore,
    Lease,
    LeaseError,
    LeaseKind,
    LeaseStore,
    Sensitivity,
    leased_task,
)
from agentboundary.model import Caps, Irreversibility, ProposedCall, Task, Tool
from agentboundary.registry import ToolRegistry

DAY = 86_400.0
T0 = 1_700_000_000.0
CAPS = Caps(max_calls=10, max_cost=10.0, max_wall_clock_s=60.0)

_TOOL = Tool(
    name="fs.read",
    arg_schema={"type": "object", "properties": {"path": {"type": "string"}}},
    irreversibility=Irreversibility.READ,
)
_HTTP = Tool(
    name="http.get",
    arg_schema={"type": "object", "properties": {"url": {"type": "string"}}},
    irreversibility=Irreversibility.READ,
)


def _task(root: Path | None, egress: set[str] | None = None, task_id: str = "t-1") -> Task:
    return Task(
        id=task_id,
        tool_scope=frozenset({"fs.read", "http.get"}),
        fs_root=None if root is None else str(root),
        egress_allowlist=frozenset(egress or set()),
        caps=CAPS,
    )


def _context(task: Task, tool: Tool, arguments: dict[str, object]) -> CallContext:
    return CallContext(
        task=task,
        tool=tool,
        proposed=ProposedCall(tool.name, arguments),
        validated_arguments=arguments,
    )


def _path_lease(subject: Path | str, now: float = T0, **overrides: object) -> Lease:
    fields: dict[str, object] = {
        "kind": LeaseKind.PATH,
        "subject": str(subject),
        "granted_by": "operator@example.test",
        "reason": "three days of access to the key directory for the rotation job",
        "granted_at": now,
        "expires_at": now + 3 * DAY,
    }
    fields.update(overrides)
    return Lease(**fields)  # type: ignore[arg-type]


def _store(*leases: Lease, now: float = T0 + DAY) -> LeaseStore:
    return InMemoryLeaseStore(leases, clock=lambda: now)


class TestAPathLeaseDoesNotAdmitItsNeighbours:
    """The near misses. A prefix comparison passes these; containment does not."""

    @pytest.fixture
    def leased(self, tmp_path: Path) -> Path:
        secrets = tmp_path / "x" / "secrets"
        secrets.mkdir(parents=True)
        (secrets / "prod.env").write_text("KEY=1", encoding="utf-8")
        (tmp_path / "x" / "secrets-backup").mkdir()
        (tmp_path / "x" / "secrets-backup" / "prod.env").write_text("KEY=1", encoding="utf-8")
        (tmp_path / "x" / "secretsX").mkdir()
        return secrets

    @pytest.fixture
    def workspace(self, tmp_path: Path) -> Path:
        root = tmp_path / "workspace"
        root.mkdir()
        return root

    @pytest.mark.parametrize(
        "near_miss",
        [
            "x/secrets-backup/prod.env",
            "x/secrets-backup",
            "x/secretsX",
            "x/secrets/../../etc/passwd",
            "x/secrets/../secrets-backup/prod.env",
            "x",
            "x/secretsandmore",
        ],
        ids=[
            "sibling-sharing-a-prefix",
            "sibling-directory",
            "sibling-one-character-longer",
            "traversal-out-of-the-lease",
            "traversal-into-the-sibling",
            "the-parent",
            "prefix-with-no-separator",
        ],
    )
    def test_a_lease_over_one_directory_admits_none_of_these(
        self, near_miss: str, leased: Path, workspace: Path, tmp_path: Path
    ) -> None:
        guard = PathConfinementGuard(leases=_store(_path_lease(leased)))
        result = guard.check(_context(_task(workspace), _TOOL, {"path": str(tmp_path / near_miss)}))
        assert not result.passed, f"{near_miss} was admitted by a lease over {leased}"
        assert result.reason is RefusalReason.PATH_OUTSIDE_ROOT
        assert "no lease admits it" in result.detail

    def test_the_refusal_reason_does_not_change_because_a_lease_was_consulted(
        self, leased: Path, workspace: Path, tmp_path: Path
    ) -> None:
        """An operator triages on the reason string; consulting a lease is a detail."""
        without = PathConfinementGuard().check(
            _context(_task(workspace), _TOOL, {"path": "/etc/passwd"})
        )
        with_store = PathConfinementGuard(leases=_store(_path_lease(leased))).check(
            _context(_task(workspace), _TOOL, {"path": "/etc/passwd"})
        )
        assert without.reason is with_store.reason is RefusalReason.PATH_OUTSIDE_ROOT

    def test_an_expired_lease_admits_nothing(self, leased: Path, workspace: Path) -> None:
        guard = PathConfinementGuard(
            leases=_store(_path_lease(leased), now=T0 + 4 * DAY),
        )
        result = guard.check(_context(_task(workspace), _TOOL, {"path": str(leased / "prod.env")}))
        assert not result.passed
        assert result.reason is RefusalReason.PATH_OUTSIDE_ROOT

    def test_a_lease_at_the_instant_of_expiry_admits_nothing(
        self, leased: Path, workspace: Path
    ) -> None:
        guard = PathConfinementGuard(leases=_store(_path_lease(leased), now=T0 + 3 * DAY))
        assert not guard.check(
            _context(_task(workspace), _TOOL, {"path": str(leased / "prod.env")})
        ).passed

    def test_a_lease_for_another_task_admits_nothing(self, leased: Path, workspace: Path) -> None:
        guard = PathConfinementGuard(leases=_store(_path_lease(leased, task_id="other-task")))
        assert not guard.check(
            _context(_task(workspace), _TOOL, {"path": str(leased / "prod.env")})
        ).passed

    def test_a_host_lease_does_not_widen_a_path_check(self, leased: Path, workspace: Path) -> None:
        host_lease = Lease(
            kind=LeaseKind.HOST,
            subject="docs.internal",
            granted_by="op",
            reason="r",
            granted_at=T0,
            expires_at=T0 + DAY,
        )
        guard = PathConfinementGuard(leases=_store(host_lease))
        assert not guard.check(
            _context(_task(workspace), _TOOL, {"path": str(leased / "prod.env")})
        ).passed

    def test_a_task_with_no_root_is_refused_before_the_store_is_reached(self, leased: Path) -> None:
        """A path lease widens a root. A task with no root has no root to widen."""
        guard = PathConfinementGuard(leases=_store(_path_lease(leased)))
        result = guard.check(_context(_task(None), _TOOL, {"path": str(leased / "prod.env")}))
        assert not result.passed
        assert "declares no fs_root" in result.detail

    def test_an_unresolvable_argument_is_refused_even_under_a_lease(
        self, leased: Path, workspace: Path
    ) -> None:
        """Undecidable means refuse, and that applies to the widening too."""
        (workspace / "loop").symlink_to(workspace / "loop")
        guard = PathConfinementGuard(leases=_store(_path_lease(leased)))
        result = guard.check(_context(_task(workspace), _TOOL, {"path": "loop/x"}))
        assert not result.passed
        assert result.reason is RefusalReason.PATH_OUTSIDE_ROOT

    def test_an_unreadable_lease_store_fails_closed_with_the_right_reason(
        self, workspace: Path
    ) -> None:
        class Broken(InMemoryLeaseStore):
            def active_paths(self, task_id: str, now: float | None = None) -> tuple[Lease, ...]:
                raise LeaseError("line 3 is not valid JSON")

        guard = PathConfinementGuard(leases=Broken((), clock=lambda: T0))
        result = guard.check(_context(_task(workspace), _TOOL, {"path": "/etc/passwd"}))
        assert not result.passed
        assert result.reason is RefusalReason.PATH_OUTSIDE_ROOT
        assert "lease store could not be read" in result.detail

    def test_an_unreadable_store_does_not_break_an_in_root_path(self, workspace: Path) -> None:
        """Leases are consulted only on the refusal branch, so ordinary work is unaffected."""

        class Broken(InMemoryLeaseStore):
            def active_paths(self, task_id: str, now: float | None = None) -> tuple[Lease, ...]:
                raise LeaseError("unreadable")

        guard = PathConfinementGuard(leases=Broken((), clock=lambda: T0))
        assert guard.check(_context(_task(workspace), _TOOL, {"path": "notes.txt"})).passed


class TestAPathLeaseAdmitsWhatItSays:
    """Without this, the guard could refuse everything and pass every test above."""

    @pytest.fixture
    def leased(self, tmp_path: Path) -> Path:
        secrets = tmp_path / "x" / "secrets"
        (secrets / "deep").mkdir(parents=True)
        (secrets / "prod.env").write_text("KEY=1", encoding="utf-8")
        return secrets

    @pytest.fixture
    def workspace(self, tmp_path: Path) -> Path:
        root = tmp_path / "workspace"
        root.mkdir()
        return root

    @pytest.mark.parametrize("relative", ["prod.env", "deep", "deep/new-file.txt", "."], ids=str)
    def test_a_live_lease_admits_its_own_subtree(
        self, relative: str, leased: Path, workspace: Path
    ) -> None:
        guard = PathConfinementGuard(leases=_store(_path_lease(leased)))
        result = guard.check(_context(_task(workspace), _TOOL, {"path": str(leased / relative)}))
        assert result.passed, result.detail

    def test_the_admitting_lease_is_named_in_the_check_detail(
        self, leased: Path, workspace: Path
    ) -> None:
        """A boundary that moved must be visible in the trace, with who moved it."""
        guard = PathConfinementGuard(leases=_store(_path_lease(leased)))
        result = guard.check(_context(_task(workspace), _TOOL, {"path": str(leased / "prod.env")}))
        assert "under lease on" in result.detail
        assert "operator@example.test" in result.detail

    def test_a_path_inside_the_root_never_consults_the_store(
        self, leased: Path, workspace: Path
    ) -> None:
        guard = PathConfinementGuard(leases=_store(_path_lease(leased)))
        result = guard.check(_context(_task(workspace), _TOOL, {"path": "notes.txt"}))
        assert result.passed
        assert "lease" not in result.detail

    def test_a_symlink_resolving_into_the_lease_is_admitted(
        self, leased: Path, workspace: Path
    ) -> None:
        """ "Resolve, then compare" cuts both ways, and the honest answer is stated."""
        (workspace / "link").symlink_to(leased)
        guard = PathConfinementGuard(leases=_store(_path_lease(leased)))
        assert guard.check(_context(_task(workspace), _TOOL, {"path": "link/prod.env"})).passed

    def test_a_symlink_inside_the_lease_pointing_out_of_it_is_refused(
        self, leased: Path, workspace: Path, tmp_path: Path
    ) -> None:
        (tmp_path / "elsewhere").mkdir()
        (leased / "escape").symlink_to(tmp_path / "elsewhere")
        guard = PathConfinementGuard(leases=_store(_path_lease(leased)))
        assert not guard.check(
            _context(_task(workspace), _TOOL, {"path": str(leased / "escape" / "f")})
        ).passed

    def test_two_arguments_are_judged_against_one_instant(
        self, leased: Path, workspace: Path
    ) -> None:
        """A store read twice could find one argument leased and the next expired."""
        ticks = iter([T0 + DAY, T0 + 900 * DAY])
        guard = PathConfinementGuard(
            leases=InMemoryLeaseStore([_path_lease(leased)], clock=lambda: next(ticks))
        )
        result = guard.check(
            _context(
                _task(workspace),
                _TOOL,
                {"path": str(leased / "prod.env"), "dest": str(leased / "deep")},
            )
        )
        assert result.passed, result.detail


class TestAHostLeaseWidensTheAllowlistAndNothingElse:
    def _lease(self, subject: str = "reports.partner.example", **overrides: object) -> Lease:
        fields: dict[str, object] = {
            "kind": LeaseKind.HOST,
            "subject": subject,
            "granted_by": "operator@example.test",
            "reason": "three days to publish the quarterly export",
            "granted_at": T0,
            "expires_at": T0 + 3 * DAY,
        }
        fields.update(overrides)
        return Lease(**fields)  # type: ignore[arg-type]

    def test_a_live_host_lease_admits_that_host(self) -> None:
        guard = EgressGuard(leases=_store(self._lease()))
        result = guard.check(
            _context(_task(None), _HTTP, {"url": "https://reports.partner.example/upload"})
        )
        assert result.passed, result.detail

    def test_the_lease_is_matched_exactly_not_as_a_suffix(self) -> None:
        guard = EgressGuard(leases=_store(self._lease("docs.internal")))
        for host in ("docs.internal.evil.example", "evil.docs.internal", "xdocs.internal"):
            result = guard.check(_context(_task(None), _HTTP, {"url": f"https://{host}/x"}))
            assert not result.passed, host
            assert result.reason is RefusalReason.EGRESS_HOST_NOT_ALLOWED

    def test_an_expired_host_lease_admits_nothing(self) -> None:
        guard = EgressGuard(leases=_store(self._lease(), now=T0 + 4 * DAY))
        assert not guard.check(
            _context(_task(None), _HTTP, {"url": "https://reports.partner.example/x"})
        ).passed

    def test_a_lease_does_not_widen_the_scheme_allowlist(self) -> None:
        guard = EgressGuard(leases=_store(self._lease("localhost")))
        result = guard.check(_context(_task(None), _HTTP, {"url": "file:///etc/passwd"}))
        assert not result.passed
        assert "scheme" in result.detail

    def test_a_lease_does_not_excuse_a_loopback_literal(self) -> None:
        """The rebinding shape stays refused; the lease widens membership only."""
        guard = EgressGuard(leases=_store(self._lease("127.0.0.1")))
        result = guard.check(_context(_task(None), _HTTP, {"url": "https://127.0.0.1/x"}))
        assert not result.passed
        assert "loopback or link-local" in result.detail

    def test_a_lease_does_not_excuse_an_address_literal_with_a_root_label(self) -> None:
        guard = EgressGuard(leases=_store(self._lease("10.1.2.3")))
        result = guard.check(_context(_task(None), _HTTP, {"url": "https://10.1.2.3./x"}))
        assert not result.passed
        assert "root label" in result.detail

    def test_a_lease_does_not_admit_a_url_with_no_host(self) -> None:
        guard = EgressGuard(leases=_store(self._lease()))
        result = guard.check(_context(_task(None), _HTTP, {"url": "https:///path"}))
        assert not result.passed
        assert "no host" in result.detail

    def test_a_path_lease_does_not_widen_an_egress_check(self) -> None:
        guard = EgressGuard(leases=_store(_path_lease("/srv/secrets")))
        assert not guard.check(
            _context(_task(None), _HTTP, {"url": "https://reports.partner.example/x"})
        ).passed

    def test_a_lease_for_another_task_admits_nothing(self) -> None:
        guard = EgressGuard(leases=_store(self._lease(task_id="other")))
        assert not guard.check(
            _context(_task(None), _HTTP, {"url": "https://reports.partner.example/x"})
        ).passed

    def test_an_unreadable_store_refuses_egress_with_the_right_reason(self) -> None:
        class Broken(InMemoryLeaseStore):
            def active_hosts(self, task_id: str, now: float | None = None) -> tuple[Lease, ...]:
                raise LeaseError("unreadable")

        guard = EgressGuard(leases=Broken((), clock=lambda: T0))
        result = guard.check(
            _context(_task(None, {"docs.internal"}), _HTTP, {"url": "https://docs.internal/x"})
        )
        assert not result.passed
        assert result.reason is RefusalReason.EGRESS_HOST_NOT_ALLOWED
        assert "lease store could not be read" in result.detail

    def test_the_refusal_detail_says_whether_a_lease_was_in_force(self) -> None:
        without = EgressGuard().check(
            _context(_task(None), _HTTP, {"url": "https://evil.example/x"})
        )
        assert "no host lease in force" not in without.detail
        with_store = EgressGuard(leases=_store(self._lease())).check(
            _context(_task(None), _HTTP, {"url": "https://evil.example/x"})
        )
        assert "lease(s) in force for reports.partner.example" in with_store.detail


class TestToolLeasesResolveAtConstructionTime:
    """I1 stays structural: the dispatch table is fixed before the loop starts."""

    def _lease(self, subject: str = "tickets.delete", **overrides: object) -> Lease:
        fields: dict[str, object] = {
            "kind": LeaseKind.TOOL,
            "subject": subject,
            "granted_by": "operator@example.test",
            "reason": "one-off cleanup of duplicate tickets, OPS-4900",
            "granted_at": T0,
            "expires_at": T0 + DAY,
            "sensitivity": Sensitivity.SENSITIVE,
        }
        fields.update(overrides)
        return Lease(**fields)  # type: ignore[arg-type]

    def test_a_live_tool_lease_widens_the_task_scope(self, tmp_path: Path) -> None:
        widened = leased_task(_task(tmp_path), _store(self._lease(), now=T0))
        assert "tickets.delete" in widened.tool_scope
        assert widened.is_in_scope("tickets.delete")

    def test_an_expired_tool_lease_does_not_widen_a_new_task(self, tmp_path: Path) -> None:
        widened = leased_task(_task(tmp_path), _store(self._lease(), now=T0 + 2 * DAY))
        assert "tickets.delete" not in widened.tool_scope

    def test_a_lease_for_another_task_does_not_widen_this_one(self, tmp_path: Path) -> None:
        widened = leased_task(_task(tmp_path), _store(self._lease(task_id="other")))
        assert "tickets.delete" not in widened.tool_scope

    def test_no_store_leaves_the_task_untouched(self, tmp_path: Path) -> None:
        task = _task(tmp_path)
        assert leased_task(task, None) is task

    def test_the_original_task_is_not_mutated(self, tmp_path: Path) -> None:
        task = _task(tmp_path)
        leased_task(task, _store(self._lease(), now=T0))
        assert "tickets.delete" not in task.tool_scope

    def test_a_tool_lease_that_expires_mid_task_keeps_its_handle(self, tmp_path: Path) -> None:
        """The consequence, asserted rather than left as prose.

        ADR-0002 says an out-of-scope tool has no handle. Removing a handle
        mid-session would make I1 a call-time filter, so the lease's expiry
        bounds when a *new* task may be built with the tool, not when a running
        one loses it. The operator's lever is to end the task.
        """
        clock = {"now": T0}
        store = InMemoryLeaseStore([self._lease()], clock=lambda: clock["now"])
        widened = leased_task(_task(tmp_path), store)
        assert widened.is_in_scope("tickets.delete")

        clock["now"] = T0 + 900 * DAY
        assert widened.is_in_scope("tickets.delete"), (
            "the running task lost its handle mid-session, which would make I1 a "
            "call-time filter -- see ADR-0002"
        )
        # A task constructed now does not get it.
        assert not leased_task(_task(tmp_path), store).is_in_scope("tickets.delete")

    def test_a_lease_cannot_conjure_an_unregistered_tool(self, tmp_path: Path) -> None:
        """Fails closed at construction, loudly, where the misconfiguration is."""
        registry = ToolRegistry([_TOOL, _HTTP])
        widened = leased_task(_task(tmp_path), _store(self._lease("nowhere.tool"), now=T0))
        with pytest.raises(TaskConstructionError, match="unregistered tool"):
            registry.scope_for(widened)
