"""Path and egress confinement (N-10, N-11, I4). Resolve, then compare."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from agentboundary.confinement import (
    ConfinementError,
    EgressGuard,
    PathConfinementGuard,
    resolve_within,
)
from agentboundary.errors import RefusalReason
from agentboundary.guards import CallContext, GuardResult
from agentboundary.model import Caps, Irreversibility, ProposedCall, Task, Tool
from agentboundary.testing import reference_registry

CAPS = Caps(max_calls=5, max_cost=10.0, max_wall_clock_s=30.0)
TOOL = Tool(name="fs.read", arg_schema={}, irreversibility=Irreversibility.READ)
HTTP_TOOL = Tool(name="http.get", arg_schema={}, irreversibility=Irreversibility.READ)


def _context(
    arguments: dict[str, object],
    root: str | None = None,
    egress: frozenset[str] = frozenset(),
    tool: Tool = TOOL,
) -> CallContext:
    task = Task(
        id="t-1",
        tool_scope=frozenset({tool.name}),
        fs_root=root,
        egress_allowlist=egress,
        caps=CAPS,
    )
    return CallContext(
        task=task,
        tool=tool,
        proposed=ProposedCall(tool.name, arguments),
        validated_arguments=arguments,
    )


class TestResolveWithin:
    def test_traversal_out_of_the_root_is_refused(self, tmp_path: Path) -> None:
        with pytest.raises(ConfinementError, match="outside root"):
            resolve_within("../../etc/passwd", tmp_path)

    def test_an_absolute_path_outside_the_root_is_refused(self, tmp_path: Path) -> None:
        with pytest.raises(ConfinementError, match="outside root"):
            resolve_within("/etc/passwd", tmp_path)

    def test_a_sibling_sharing_a_name_prefix_is_refused(self, tmp_path: Path) -> None:
        """A string prefix compare would accept this. relative_to does not."""
        root = tmp_path / "data"
        root.mkdir()
        (tmp_path / "data-backup").mkdir()
        with pytest.raises(ConfinementError, match="outside root"):
            resolve_within(str(tmp_path / "data-backup" / "secrets"), root)

    def test_a_symlink_escaping_the_root_is_refused(self, tmp_path: Path) -> None:
        """The whole reason resolution precedes comparison."""
        root = tmp_path / "root"
        root.mkdir()
        outside = tmp_path / "outside"
        outside.mkdir()
        (outside / "secret.txt").write_text("s", encoding="utf-8")
        (root / "link").symlink_to(outside)
        with pytest.raises(ConfinementError, match="outside root"):
            resolve_within("link/secret.txt", root)

    def test_a_symlinked_parent_cannot_smuggle_the_final_component_out(
        self, tmp_path: Path
    ) -> None:
        """strict=False still resolves the parent chain fully."""
        root = tmp_path / "root"
        root.mkdir()
        outside = tmp_path / "outside"
        outside.mkdir()
        (root / "link").symlink_to(outside)
        with pytest.raises(ConfinementError, match="outside root"):
            resolve_within("link/not-created-yet.txt", root)

    def test_parent_segments_in_a_non_existent_tail_cannot_escape(self, tmp_path: Path) -> None:
        """Regression: resolving the existing prefix and re-appending the tail
        leaves `..` uncollapsed, so this stays lexically inside the root while
        pointing outside it. Component-wise resolution is what closes it."""
        root = tmp_path / "root"
        root.mkdir()
        (tmp_path / "etc").mkdir()
        (tmp_path / "etc" / "passwd").write_text("secret", encoding="utf-8")
        with pytest.raises(ConfinementError, match="outside root"):
            resolve_within("nonexistent/../../etc/passwd", root)

    def test_a_symlink_loop_is_refused_not_silently_accepted(self, tmp_path: Path) -> None:
        """Regression: resolve(strict=False) gives up on a loop and returns the
        path unresolved, which then passes containment. Undecidable must refuse."""
        root = tmp_path / "root"
        root.mkdir()
        (root / "loop").symlink_to(root / "loop")
        # CPython raises OSError(ELOOP) on macOS and RuntimeError on Linux for
        # the same condition. Both are normalised to ConfinementError so the
        # refusal reason does not depend on the platform.
        with pytest.raises(ConfinementError, match="could not be resolved"):
            resolve_within("loop/x", root)

    def test_a_dangling_symlink_is_refused(self, tmp_path: Path) -> None:
        """It cannot be resolved, so it cannot be confined -- and its target
        may be created later, outside the root."""
        root = tmp_path / "root"
        root.mkdir()
        (root / "dangling").symlink_to(tmp_path / "not-there" / "x")
        with pytest.raises(ConfinementError, match="target does not exist"):
            resolve_within("dangling", root)

    def test_parent_of_a_symlinked_directory_is_the_targets_parent(self, tmp_path: Path) -> None:
        """`..` applies to the resolved location, matching kernel semantics."""
        root = tmp_path / "root"
        (root / "real").mkdir(parents=True)
        (root / "alias").symlink_to(root / "real")
        assert resolve_within("alias/..", root) == root.resolve()

    def test_a_path_inside_the_root_resolves(self, tmp_path: Path) -> None:
        resolved = resolve_within("a/b.txt", tmp_path)
        assert resolved == (tmp_path / "a" / "b.txt").resolve()

    def test_a_traversal_that_returns_inside_is_permitted(self, tmp_path: Path) -> None:
        """Confinement is about where you land, not the spelling you used."""
        assert resolve_within("a/../b.txt", tmp_path) == (tmp_path / "b.txt").resolve()

    def test_a_not_yet_existing_file_inside_the_root_resolves(self, tmp_path: Path) -> None:
        """A write tool legitimately targets a file that does not exist yet."""
        assert resolve_within("new/file.txt", tmp_path).name == "file.txt"


class TestPathConfinementGuard:
    def test_a_traversal_argument_is_refused(self, tmp_path: Path) -> None:
        result = PathConfinementGuard().check(
            _context({"path": "../../etc/passwd"}, root=str(tmp_path))
        )
        assert not result.passed
        assert result.reason is RefusalReason.PATH_OUTSIDE_ROOT

    def test_a_task_without_a_root_refuses_every_path_argument(self) -> None:
        """A task that did not declare a root did not ask for filesystem access."""
        result = PathConfinementGuard().check(_context({"path": "anything"}, root=None))
        assert not result.passed
        assert "declares no fs_root" in result.detail

    def test_all_recognised_path_arguments_are_checked_not_just_the_first(
        self, tmp_path: Path
    ) -> None:
        result = PathConfinementGuard().check(
            _context({"src": "ok.txt", "dest": "/etc/shadow"}, root=str(tmp_path))
        )
        assert not result.passed
        assert "dest" in result.detail

    def test_a_non_string_path_argument_is_left_to_the_schema(self, tmp_path: Path) -> None:
        """A guard second-guessing the validated type would disagree with the schema."""
        assert PathConfinementGuard().check(_context({"path": 42}, root=str(tmp_path))).passed

    def test_a_call_with_no_path_arguments_passes(self, tmp_path: Path) -> None:
        result = PathConfinementGuard().check(_context({"query": "x"}, root=str(tmp_path)))
        assert result.passed
        assert result.detail == "no path arguments"

    def test_a_path_inside_the_root_passes(self, tmp_path: Path) -> None:
        assert (
            PathConfinementGuard().check(_context({"path": "notes.txt"}, root=str(tmp_path))).passed
        )

    def test_an_unresolvable_path_is_refused_rather_than_passed(self, tmp_path: Path) -> None:
        """A symlink loop is undecidable, and undecidable means refuse."""
        root = tmp_path / "root"
        root.mkdir()
        (root / "loop").symlink_to(root / "loop")
        result = PathConfinementGuard().check(_context({"path": "loop/x"}, root=str(root)))
        assert not result.passed
        assert result.reason is RefusalReason.PATH_OUTSIDE_ROOT

    def test_the_watched_argument_names_are_configurable(self, tmp_path: Path) -> None:
        guard = PathConfinementGuard(argument_names={"archive"})
        assert not guard.check(_context({"archive": "/etc/passwd"}, root=str(tmp_path))).passed


def _declared_path_bound() -> int:
    """The catalogue's own maxLength for a path, read from the schema it ships."""
    bounds = {
        int(tool.arg_schema["properties"]["path"]["maxLength"])
        for tool in reference_registry()
        if "path" in tool.arg_schema.get("properties", {})
    }
    assert len(bounds) == 1, f"the catalogue declares more than one path bound: {sorted(bounds)}"
    return bounds.pop()


class TestTheDeclaredPathBoundHolds:
    """A schema may not promise a length the filesystem beneath it refuses (N-40).

    The generated benign corpus submitted a path of exactly the declared
    ``maxLength``, then watched the OS refuse to resolve it. The guard's
    behaviour was right and is unchanged below: an unresolvable path is
    undecidable, and undecidable means refuse. What changed is the number, so
    that passing validation and being resolvable stop being different claims.
    """

    def test_a_path_the_filesystem_cannot_resolve_is_still_refused(self, tmp_path: Path) -> None:
        """Fail closed. The bound is a promise about the schema, not a relaxation."""
        result = PathConfinementGuard().check(_context({"path": "p" * 4096}, root=str(tmp_path)))
        assert not result.passed
        assert result.reason is RefusalReason.PATH_OUTSIDE_ROOT
        assert "could not be resolved" in result.detail

    def test_a_component_over_the_bound_is_still_refused(self, tmp_path: Path) -> None:
        """One character past NAME_MAX is already unresolvable on ext4 and APFS."""
        result = PathConfinementGuard().check(_context({"path": "p" * 256}, root=str(tmp_path)))
        assert not result.passed
        assert result.reason is RefusalReason.PATH_OUTSIDE_ROOT

    def test_the_declared_bound_resolves_as_a_single_component(self, tmp_path: Path) -> None:
        """The worst-case shape: the whole argument is one filename."""
        bound = _declared_path_bound()
        result = PathConfinementGuard().check(_context({"path": "p" * bound}, root=str(tmp_path)))
        assert result.passed, result.detail

    def test_the_declared_bound_resolves_as_a_nested_path(self, tmp_path: Path) -> None:
        """And the shape a real caller uses, at exactly the same length."""
        bound = _declared_path_bound()
        segments = ["s" * 15] * (bound // 16)
        candidate = "/".join(segments)
        candidate += "/" + "f" * (bound - len(candidate) - 1)
        assert len(candidate) == bound
        result = PathConfinementGuard().check(_context({"path": candidate}, root=str(tmp_path)))
        assert result.passed, result.detail

    def test_the_bound_leaves_room_for_a_root_under_the_platform_ceiling(
        self, tmp_path: Path
    ) -> None:
        """PATH_MAX bounds the *resolved* path, and the schema cannot see the root.

        Asserted against the running platform rather than a constant: this is
        the check that fails if the number is ported to a tighter filesystem.
        """
        bound = _declared_path_bound()
        assert bound <= os.pathconf(tmp_path, "PC_NAME_MAX")
        assert bound + len(str(tmp_path)) + 1 <= os.pathconf(tmp_path, "PC_PATH_MAX")


class TestEgressGuard:
    def test_an_empty_allowlist_denies_all_egress(self) -> None:
        """The correct default: a task that needs the network says so."""
        result = EgressGuard().check(
            _context({"url": "https://example.com/x"}, egress=frozenset(), tool=HTTP_TOOL)
        )
        assert not result.passed
        assert result.reason is RefusalReason.EGRESS_HOST_NOT_ALLOWED
        assert "egress denied" in result.detail

    def test_an_unlisted_host_is_refused(self) -> None:
        result = EgressGuard().check(
            _context(
                {"url": "https://evil.example/steal"},
                egress=frozenset({"api.internal"}),
                tool=HTTP_TOOL,
            )
        )
        assert not result.passed
        assert "evil.example" in result.detail

    def test_a_non_http_scheme_is_refused(self) -> None:
        """file://, gopher:// and data: have each been someone's exfiltration channel."""
        for url in ("file:///etc/passwd", "gopher://h/x", "data:text/plain,hi"):
            result = EgressGuard().check(
                _context({"url": url}, egress=frozenset({"h"}), tool=HTTP_TOOL)
            )
            assert not result.passed, url

    def test_a_url_without_a_host_is_refused(self) -> None:
        result = EgressGuard().check(
            _context({"url": "https:///path"}, egress=frozenset({"x"}), tool=HTTP_TOOL)
        )
        assert not result.passed
        assert "declares no host" in result.detail

    def test_an_allowlisted_loopback_literal_is_still_refused(self) -> None:
        """An allowlist entry pointing at the host itself is the rebinding shape."""
        result = EgressGuard().check(
            _context(
                {"url": "http://127.0.0.1:8080/x"}, egress=frozenset({"127.0.0.1"}), tool=HTTP_TOOL
            )
        )
        assert not result.passed
        assert "loopback" in result.detail

    def test_a_link_local_literal_is_refused(self) -> None:
        """169.254.169.254 is the cloud metadata endpoint."""
        result = EgressGuard().check(
            _context(
                {"url": "http://169.254.169.254/latest/meta-data/"},
                egress=frozenset({"169.254.169.254"}),
                tool=HTTP_TOOL,
            )
        )
        assert not result.passed

    def test_an_allowlisted_host_passes(self) -> None:
        assert (
            EgressGuard()
            .check(
                _context(
                    {"url": "https://api.internal/v1/tickets"},
                    egress=frozenset({"api.internal"}),
                    tool=HTTP_TOOL,
                )
            )
            .passed
        )

    def test_host_matching_is_case_insensitive(self) -> None:
        assert (
            EgressGuard()
            .check(
                _context(
                    {"url": "https://API.Internal/v1"},
                    egress=frozenset({"api.internal"}),
                    tool=HTTP_TOOL,
                )
            )
            .passed
        )

    def test_a_subdomain_of_an_allowlisted_host_is_refused(self) -> None:
        """Allowlisting a host must not silently allowlist everything beneath it."""
        result = EgressGuard().check(
            _context(
                {"url": "https://evil.api.internal/x"},
                egress=frozenset({"api.internal"}),
                tool=HTTP_TOOL,
            )
        )
        assert not result.passed

    def test_userinfo_cannot_disguise_the_real_host(self) -> None:
        """https://api.internal@evil.example/ goes to evil.example."""
        result = EgressGuard().check(
            _context(
                {"url": "https://api.internal@evil.example/x"},
                egress=frozenset({"api.internal"}),
                tool=HTTP_TOOL,
            )
        )
        assert not result.passed
        assert "evil.example" in result.detail

    def test_a_call_with_no_url_arguments_passes(self) -> None:
        result = EgressGuard().check(_context({"path": "x"}, tool=HTTP_TOOL))
        assert result.passed
        assert result.detail == "no url arguments"


def _egress(url: str, allowlist: set[str]) -> GuardResult:
    return EgressGuard().check(_context({"url": url}, egress=frozenset(allowlist), tool=HTTP_TOOL))


class TestEgressRootLabel:
    """The DNS root label, on both sides of the comparison (N-39, I4).

    ``docs.internal.`` is ``docs.internal`` fully qualified, and refusing it was
    a false refusal with a real cost -- 6 of the 8 refusals the generated benign
    corpus found. The refusals below are the reason the fix is a normalisation
    of both sides and not a suffix rule: every one of them is a *different*
    host that the dot must not talk its way past.
    """

    def test_a_neighbouring_registrable_name_is_still_refused(self) -> None:
        """The classic near miss: the allowlisted name as a *prefix* of another."""
        for host in ("docs.internal.evil.example", "docs.internal.evil.example."):
            result = _egress(f"https://{host}/x", {"docs.internal"})
            assert not result.passed, host
            assert result.reason is RefusalReason.EGRESS_HOST_NOT_ALLOWED
            assert "not allowlisted" in result.detail

    def test_a_subdomain_of_the_allowlisted_name_is_still_refused(self) -> None:
        """Qualifying it changes nothing: matching is exact, not by suffix."""
        result = _egress("https://evil.docs.internal./x", {"docs.internal"})
        assert not result.passed
        assert result.reason is RefusalReason.EGRESS_HOST_NOT_ALLOWED

    def test_an_empty_final_label_cannot_inherit_the_allowlist(self) -> None:
        """``docs.internal..`` is not a name. Only one root label is ever removed."""
        result = _egress("https://docs.internal../x", {"docs.internal"})
        assert not result.passed
        assert result.reason is RefusalReason.EGRESS_HOST_NOT_ALLOWED

    def test_a_percent_encoded_dot_is_not_a_root_label(self) -> None:
        """Normalisation is one defined transform, not a decoder for spellings."""
        result = _egress("https://docs.internal%2e/x", {"docs.internal"})
        assert not result.passed
        assert result.reason is RefusalReason.EGRESS_HOST_NOT_ALLOWED

    def test_a_root_label_in_the_userinfo_cannot_disguise_the_host(self) -> None:
        result = _egress("https://docs.internal.@evil.example/x", {"docs.internal"})
        assert not result.passed
        assert "evil.example" in result.detail

    def test_a_host_that_is_only_the_root_label_is_refused(self) -> None:
        """Even allowlisted as ``.``: the root is not a destination."""
        result = _egress("https://./x", {"."})
        assert not result.passed
        assert "declares no host" in result.detail

    def test_an_address_literal_carrying_a_root_label_is_refused(self) -> None:
        """A literal is not a DNS name, so the dot means whatever the client says.

        A WHATWG parser drops it and connects to 10.1.2.3; ``getaddrinfo`` asks
        a resolver for the name ``10.1.2.3.``. Two destinations, one string.
        """
        result = _egress("https://10.1.2.3./x", {"10.1.2.3"})
        assert not result.passed
        assert result.reason is RefusalReason.EGRESS_HOST_NOT_ALLOWED
        assert "address literal" in result.detail

    def test_the_root_label_cannot_disarm_the_loopback_rule(self) -> None:
        """The bug this fix also closes.

        Before normalisation, ``_as_ip('127.0.0.1.')`` returned ``None``, so an
        allowlist written in the qualified spelling skipped the loopback and
        link-local check entirely.
        """
        for host in ("127.0.0.1", "169.254.169.254"):
            for url_host, entry in ((f"{host}.", f"{host}."), (host, f"{host}.")):
                result = _egress(f"http://{url_host}/latest/meta-data/", {entry})
                assert not result.passed, (url_host, entry)
                assert result.reason is RefusalReason.EGRESS_HOST_NOT_ALLOWED

    def test_the_qualified_spelling_of_an_allowlisted_host_is_authorised(self) -> None:
        """The false refusal itself: same host, request would have succeeded."""
        assert _egress("https://docs.internal./x", {"docs.internal"}).passed

    def test_a_qualified_allowlist_entry_admits_the_unqualified_url(self) -> None:
        """The other side of the same normalisation."""
        assert _egress("https://docs.internal/x", {"docs.internal."}).passed

    def test_both_sides_qualified_is_authorised(self) -> None:
        assert _egress("https://DOCS.INTERNAL./x", {"docs.internal."}).passed

    def test_a_routable_literal_is_unaffected(self) -> None:
        assert _egress("https://10.1.2.3/x", {"10.1.2.3"}).passed
        assert _egress("https://10.1.2.3/x", {"10.1.2.3."}).passed
