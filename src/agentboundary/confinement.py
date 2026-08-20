"""Filesystem and egress confinement -- invariant I4, FR-009 to FR-011.

Two guards, one principle: **resolve, then compare**. Never pattern-match.

String inspection of a requested path is not a confinement mechanism. It is a
denylist of the traversal spellings its author happened to think of, and the
supply of spellings is larger than the author -- ``..``, encoded separators,
a symlink that is perfectly ordinary until someone repoints it. Resolution
collapses all of that to one canonical answer before anything is compared.
"""

from __future__ import annotations

import ipaddress
import os
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any, Final
from urllib.parse import urlsplit

from agentboundary.errors import RefusalReason
from agentboundary.guards import CallContext, GuardResult

__all__ = ["EgressGuard", "PathConfinementGuard", "resolve_within"]

#: Argument names treated as paths. Explicit rather than inferred: a guard that
#: guesses which arguments are path-shaped will eventually guess wrong in the
#: permissive direction.
DEFAULT_PATH_ARGUMENTS: Final[frozenset[str]] = frozenset(
    {"path", "file", "filename", "filepath", "src", "dest", "destination", "target"}
)

DEFAULT_URL_ARGUMENTS: Final[frozenset[str]] = frozenset({"url", "uri", "endpoint", "href"})

#: Schemes that can reach the network or the filesystem through a URL argument.
#: Anything not here is refused rather than passed through: file://, gopher://
#: and data: have all been exfiltration channels in someone's incident report.
ALLOWED_SCHEMES: Final[frozenset[str]] = frozenset({"http", "https"})


class ConfinementError(Exception):
    """A path could not be resolved into the configured root."""


def _resolve_fully(path: Path) -> Path:
    """Resolve an absolute path one component at a time, refusing the undecidable.

    Neither shortcut works here.

    ``Path.resolve(strict=False)`` gives up quietly on a component it cannot
    resolve -- a symlink loop, a broken link -- and hands back a path that only
    *looks* resolved. Confining that answer means confining a value resolution
    never produced.

    Resolving the deepest existing ancestor and re-appending the rest is worse:
    it leaves ``..`` segments in the tail uncollapsed, so
    ``<root>/nonexistent/../../etc/passwd`` stays lexically inside the root and
    passes containment while pointing outside it.

    So walk down instead. At each step, a symlink is resolved strictly, which
    raises on a loop or a dangling target rather than swallowing it, and ``..``
    is applied to the *resolved* location -- the same order the kernel uses. A
    component that does not exist is carried forward as-is; it cannot be a
    symlink, because a symlink exists even when its target does not.

    Raises:
        ConfinementError: a component is a symlink whose target does not exist.
        OSError: resolution failed and the result is undecidable -- a symlink
            loop, or a permission error on a parent.
    """
    parts = path.parts
    current = Path(parts[0]).resolve(strict=True)
    for part in parts[1:]:
        if part == os.pardir:
            current = current.parent
            continue
        if part == os.curdir:
            continue
        candidate = current / part
        if candidate.is_symlink():
            try:
                current = candidate.resolve(strict=True)
            except FileNotFoundError as exc:
                msg = (
                    f"{candidate} is a symlink whose target does not exist, so it "
                    f"cannot be resolved and therefore cannot be confined"
                )
                raise ConfinementError(msg) from exc
        else:
            current = candidate
    return current


def resolve_within(candidate: str, root: Path) -> Path:
    """Resolve ``candidate`` and return it only if it lies inside ``root``.

    Resolution happens **first** -- symlinks followed, ``..`` collapsed,
    relative segments applied -- and the containment test runs on the result
    (FR-009). Comparing before resolving is the classic mistake: it accepts
    ``/srv/data/../../etc/passwd`` because the prefix matches.

    A path whose final components do not exist is legitimate -- a write tool
    targets a file that is not there yet -- but the existing part of the chain
    is resolved strictly, so a symlinked directory cannot smuggle the final
    component out of the root.

    Raises:
        ConfinementError: the resolved path lies outside the root, or a
            component could not be resolved at all.
        OSError: resolution failed for a reason the caller must treat as
            undecidable, such as a symlink loop.
    """
    resolved_root = root.resolve(strict=True)
    target = Path(candidate)
    absolute = target if target.is_absolute() else resolved_root / target
    resolved = _resolve_fully(absolute)

    # relative_to is the containment test rather than a string prefix compare:
    # `/srv/data-backup` must not count as inside `/srv/data`, and a prefix
    # comparison says it does.
    try:
        resolved.relative_to(resolved_root)
    except ValueError as exc:
        msg = f"{candidate!r} resolves to {resolved} which is outside root {resolved_root}"
        raise ConfinementError(msg) from exc
    return resolved


class PathConfinementGuard:
    """Refuses any path argument that resolves outside the task's root (I4).

    Runs before a handler is reached, so refusal precedes any file being opened
    (FR-011). A task with no ``fs_root`` refuses every path argument outright:
    a task that did not declare a root did not ask for filesystem access.
    """

    __slots__ = ("_argument_names",)

    def __init__(self, argument_names: Iterable[str] = DEFAULT_PATH_ARGUMENTS) -> None:
        self._argument_names = frozenset(argument_names)

    @property
    def name(self) -> str:
        return "path_confinement"

    def check(self, context: CallContext) -> GuardResult:
        candidates = _string_arguments(context.validated_arguments, self._argument_names)
        if not candidates:
            return GuardResult.ok("no path arguments")

        if context.task.fs_root is None:
            return GuardResult.refuse(
                RefusalReason.PATH_OUTSIDE_ROOT,
                f"task {context.task.id!r} declares no fs_root, so path argument(s) "
                f"{', '.join(sorted(candidates))} cannot be confined",
            )

        root = Path(context.task.fs_root)
        for argument, value in sorted(candidates.items()):
            try:
                resolve_within(value, root)
            except ConfinementError as exc:
                return GuardResult.refuse(
                    RefusalReason.PATH_OUTSIDE_ROOT, f"argument {argument!r}: {exc}"
                )
            except OSError as exc:
                # Resolution itself failed -- a symlink loop, a permission
                # error on a parent. Undecidable, therefore refused.
                return GuardResult.refuse(
                    RefusalReason.PATH_OUTSIDE_ROOT,
                    f"argument {argument!r}: could not be resolved ({exc}); refusing rather "
                    f"than proceeding on an unresolved path",
                )
        return GuardResult.ok(f"{len(candidates)} path argument(s) within root")


class EgressGuard:
    """Refuses any destination host absent from the task's allowlist (I4).

    The host is taken from the **post-validation** URL (FR-010), and the check
    precedes socket creation (FR-011).

    An empty allowlist denies all egress. That is the correct default: a task
    that needs the network says so.
    """

    __slots__ = ("_argument_names",)

    def __init__(self, argument_names: Iterable[str] = DEFAULT_URL_ARGUMENTS) -> None:
        self._argument_names = frozenset(argument_names)

    @property
    def name(self) -> str:
        return "egress_allowlist"

    def check(self, context: CallContext) -> GuardResult:
        candidates = _string_arguments(context.validated_arguments, self._argument_names)
        if not candidates:
            return GuardResult.ok("no url arguments")

        allowlist = context.task.egress_allowlist
        for argument, value in sorted(candidates.items()):
            refusal = self._check_one(argument, value, allowlist)
            if refusal is not None:
                return refusal
        return GuardResult.ok(f"{len(candidates)} destination(s) allowlisted")

    def _check_one(
        self, argument: str, value: str, allowlist: frozenset[str]
    ) -> GuardResult | None:
        try:
            parts = urlsplit(value)
        except ValueError as exc:
            return GuardResult.refuse(
                RefusalReason.EGRESS_HOST_NOT_ALLOWED,
                f"argument {argument!r}: unparseable URL ({exc})",
            )

        if parts.scheme.lower() not in ALLOWED_SCHEMES:
            return GuardResult.refuse(
                RefusalReason.EGRESS_HOST_NOT_ALLOWED,
                f"argument {argument!r}: scheme {parts.scheme!r} is not one of "
                f"{', '.join(sorted(ALLOWED_SCHEMES))}",
            )

        host = (parts.hostname or "").lower()
        if not host:
            return GuardResult.refuse(
                RefusalReason.EGRESS_HOST_NOT_ALLOWED,
                f"argument {argument!r}: URL declares no host",
            )

        if host not in {entry.lower() for entry in allowlist}:
            return GuardResult.refuse(
                RefusalReason.EGRESS_HOST_NOT_ALLOWED,
                f"argument {argument!r}: host {host!r} is not allowlisted "
                f"({', '.join(sorted(allowlist)) or 'allowlist is empty: egress denied'})",
            )

        # An allowlisted *name* that resolves to a loopback or link-local
        # address is the DNS-rebinding shape. Literal addresses are all we can
        # judge deterministically here; name resolution belongs to the caller
        # making the request, and this limitation is stated in the threat model.
        literal = _as_ip(host)
        if literal is not None and (literal.is_loopback or literal.is_link_local):
            return GuardResult.refuse(
                RefusalReason.EGRESS_HOST_NOT_ALLOWED,
                f"argument {argument!r}: {host!r} is a loopback or link-local literal",
            )
        return None


def _string_arguments(arguments: Mapping[str, Any], names: frozenset[str]) -> dict[str, str]:
    """Collect the named arguments that are strings.

    Non-string values are left alone: schema validation already decided the
    type, and a guard second-guessing it would disagree with the schema.
    """
    return {
        name: value for name, value in arguments.items() if name in names and isinstance(value, str)
    }


def _as_ip(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return None
