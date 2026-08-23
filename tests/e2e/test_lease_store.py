"""End-to-end: an operator's lease file, on disk, out of the agent's reach (N-42).

The store is an operator artifact. These exercise it the way one is actually
used -- written out of band, read back by a process that did not write it,
revoked by editing the file -- rather than through a seeded in-memory list.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agentboundary.confinement import StoreWithinReachError, assert_out_of_reach
from agentboundary.leases import (
    FileLeaseStore,
    Lease,
    LeaseError,
    LeaseKind,
    Sensitivity,
    describe,
)

pytestmark = pytest.mark.e2e

DAY = 86_400.0
T0 = 1_700_000_000.0


def _write(path: Path, *leases: Lease) -> None:
    """Write the store the way an operator's grant command would: append a line."""
    path.write_text(
        "".join(json.dumps(lease.to_json(), sort_keys=True) + "\n" for lease in leases),
        encoding="utf-8",
    )


def _three_day_credential_lease() -> Lease:
    return Lease.granted(
        kind=LeaseKind.PATH,
        subject="/srv/agent-boundary/secrets",
        granted_by="operator@example.test",
        reason="nightly rotation automation needs the key directory for three days, OPS-4821",
        granted_at=T0,
        duration_s=3 * DAY,
    )


class TestTheOperatorsFileIsTheSourceOfTruth:
    def test_a_lease_written_out_of_band_is_read_back_intact(self, tmp_path: Path) -> None:
        path = tmp_path / "leases" / "granted.jsonl"
        path.parent.mkdir()
        _write(path, _three_day_credential_lease())

        active = FileLeaseStore(path, clock=lambda: T0 + DAY).active(LeaseKind.PATH, "ops")

        assert len(active) == 1
        assert active[0].subject == "/srv/agent-boundary/secrets"
        assert active[0].granted_by == "operator@example.test"
        assert active[0].sensitivity is Sensitivity.CREDENTIAL

    def test_the_lease_stops_authorising_the_moment_its_window_closes(self, tmp_path: Path) -> None:
        path = tmp_path / "granted.jsonl"
        _write(path, _three_day_credential_lease())
        store = FileLeaseStore(path, clock=lambda: T0 + 3 * DAY)
        assert store.active(LeaseKind.PATH, "ops") == ()
        assert len(store.expired()) == 1

    def test_removing_the_line_revokes_without_a_restart(self, tmp_path: Path) -> None:
        path = tmp_path / "granted.jsonl"
        _write(path, _three_day_credential_lease())
        store = FileLeaseStore(path, clock=lambda: T0 + DAY)
        assert store.active(LeaseKind.PATH, "ops") != ()
        _write(path)
        assert store.active(LeaseKind.PATH, "ops") == ()

    def test_a_corrupted_store_refuses_loudly_rather_than_reading_as_empty(
        self, tmp_path: Path
    ) -> None:
        """An empty read and an unreadable file must not look the same to an operator."""
        path = tmp_path / "granted.jsonl"
        _write(path, _three_day_credential_lease())
        with path.open("a", encoding="utf-8") as handle:
            handle.write("{oh no\n")
        with pytest.raises(LeaseError, match="not valid JSON"):
            FileLeaseStore(path, clock=lambda: T0 + DAY).active(LeaseKind.PATH, "ops")

    def test_what_is_granted_is_visible_with_time_remaining(self, tmp_path: Path) -> None:
        """An operator who cannot see what is granted cannot revoke it."""
        path = tmp_path / "granted.jsonl"
        _write(path, _three_day_credential_lease())
        store = FileLeaseStore(path, clock=lambda: T0 + 2 * DAY)
        text = describe(store.leases(), store.now())
        assert "/srv/agent-boundary/secrets" in text
        assert "credential" in text
        assert "24.0h remaining" in text


class TestTheStoreLivesWhereTheAgentCannotWrite:
    def test_a_lease_file_inside_the_task_root_is_refused(self, tmp_path: Path) -> None:
        root = tmp_path / "workspace"
        root.mkdir()
        path = root / "granted.jsonl"
        _write(path, _three_day_credential_lease())
        with pytest.raises(StoreWithinReachError, match="resolves inside fs_root"):
            assert_out_of_reach(FileLeaseStore(path).path, str(root), "lease store")

    def test_a_lease_file_beside_the_root_is_accepted(self, tmp_path: Path) -> None:
        root = tmp_path / "workspace"
        root.mkdir()
        (tmp_path / "workspace-backup").mkdir()
        path = tmp_path / "workspace-backup" / "granted.jsonl"
        _write(path, _three_day_credential_lease())
        assert_out_of_reach(FileLeaseStore(path).path, str(root), "lease store")
