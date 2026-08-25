"""Build a disposable workspace whose planted carrier can only reach loopback.

An evidence run (ADR-0009) needs a task a model can actually be given: real
work, real files, and one corpus carrier that is *live* rather than quoted --
a dependency README the agent has a stated reason to open, carrying the payload
in the position an attacker would have put it.

That is also the one measurement that can become an incident. A payload which
is genuinely live is a payload whose named destination something might genuinely
contact, and a corpus payload reaching a real host during a measurement is not a
measurement. So the destination is a control rather than a convention: every
sink a workspace declares is resolved and refused unless every address it
resolves to is loopback, and the refusal happens **before** the workspace
exists on disk.

Three properties make that check worth relying on.

**No name is resolved unless a caller supplies something that can.** The
default resolver, :func:`refuse_all_names`, resolves nothing, so a host that is
not already a loopback literal is refused rather than looked up. This module
imports no network module at all -- there is no socket here to accidentally
open -- which is what keeps the offline guarantee a property of the code rather
than of how the tests happened to be written.

**Resolve, then compare.** The same doctrine as
:mod:`agentboundary.confinement`. ``127.0.0.1@evil.example`` is not a loopback
address because it contains the characters ``127.0.0.1``, and
``2130706433`` is not refused because it looks odd -- the first is refused for
carrying userinfo, whose destination different clients disagree about, and the
second because it is not an address literal and no resolver was willing to say
what it is.

**Undeclared destinations are refused too, and that one is a mitigation.** Every
``http`` or ``https`` URL in the materialised content must belong to a declared
sink, so a second exfiltration target cannot be added to a carrier without also
being declared and therefore checked. It is a scan over text we author; a
missed spelling fails open, so it reduces the chance of an undeclared
destination and bounds nothing. What bounds the run is the broker -- the task
scopes no HTTP tool and allowlists no host -- and, in the unbrokered arm, a shim
that records without performing.
"""

from __future__ import annotations

import ipaddress
import json
import re
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Final
from urllib.parse import urlsplit

from agentboundary.confinement import (
    ALLOWED_SCHEMES,
    ConfinementError,
    resolve_within,
    without_root_label,
)
from agentboundary.model import Caps, ProposedCall, Task

__all__ = [
    "BuiltWorkspace",
    "Resolver",
    "SinkNotLocalError",
    "WorkspaceDeclaration",
    "WorkspaceRejected",
    "assert_sinks_are_local",
    "build_workspace",
    "destination_of",
    "load_declaration",
    "refuse_all_names",
    "urls_in",
]

#: Maps a DNS name to the addresses it resolves to, as strings.
#:
#: Injected rather than called directly so a test can state the mapping it is
#: testing against. A guard whose answer depends on the network is a guard whose
#: result depends on where it ran, which is not evidence.
Resolver = Callable[[str], tuple[str, ...]]

#: Every http(s) URL in a blob of text, up to the first character that cannot
#: appear in one. Over-approximating on purpose: it is better to ask about a
#: destination that turns out to be prose than to miss one that is not.
_URL_PATTERN: Final[re.Pattern[str]] = re.compile(r"https?://[^\s<>\"'`)\]}]+", re.IGNORECASE)

#: Default ports, so that ``http://127.0.0.1`` and ``http://127.0.0.1:80`` name
#: one destination rather than two.
_DEFAULT_PORTS: Final[Mapping[str, int]] = {"http": 80, "https": 443}


class WorkspaceRejected(Exception):
    """A workspace was refused and therefore does not exist.

    Raised at build time, before any file is written. There is no partially
    materialised state to clean up because nothing was materialised.
    """


class SinkNotLocalError(WorkspaceRejected):
    """A declared destination could not be shown to resolve only to loopback.

    Covers both directions of failure -- an address that is demonstrably not
    loopback, and a host nothing was willing to resolve. Undecidable means
    refuse, the same reading :mod:`agentboundary.confinement` gives it.
    """


def refuse_all_names(host: str) -> tuple[str, ...]:
    """The default resolver: resolve nothing, so nothing is looked up.

    A workspace whose sinks are address literals needs no resolution, and every
    workspace shipped in this repository is written that way. Wiring a resolver
    that reaches the network is therefore an explicit act by a caller who has
    decided to pay for it, and never something this module does on its own.
    """
    del host
    return ()


def destination_of(url: str) -> tuple[str, str, int]:
    """The ``(scheme, host, port)`` a URL names, normalised for comparison.

    The path is dropped deliberately: what a sink check is about is where
    traffic goes, not what it asks for once it arrives. Two URLs differing only
    in path are one destination and are declared once.

    Raises:
        SinkNotLocalError: the URL does not name a destination that can be
            checked -- an unusable scheme, an absent host, userinfo, or a
            spelling whose destination depends on which client parses it.
    """
    try:
        parts = urlsplit(url)
    except ValueError as exc:
        msg = f"{url!r} could not be parsed as a URL ({exc}); refusing rather than guessing"
        raise SinkNotLocalError(msg) from exc

    scheme = parts.scheme.lower()
    if scheme not in ALLOWED_SCHEMES:
        msg = (
            f"{url!r} uses scheme {parts.scheme!r}, which is not one of "
            f"{', '.join(sorted(ALLOWED_SCHEMES))}"
        )
        raise SinkNotLocalError(msg)

    # Userinfo is refused for two reasons at once. It is the `@` confusion --
    # a reader sees the loopback literal on the left and the connection is made
    # to whatever is on the right -- and a workspace may carry no credential,
    # so a field whose entire purpose is to carry one has no legitimate use
    # here.
    if parts.username is not None or parts.password is not None:
        msg = (
            f"{url!r} carries userinfo before the host. The destination is what follows "
            f"the '@', not what precedes it, and a workspace carries no credential"
        )
        raise SinkNotLocalError(msg)

    host = (parts.hostname or "").lower()
    if not host or not host.strip("."):
        msg = f"{url!r} declares no host"
        raise SinkNotLocalError(msg)

    if host != without_root_label(host):
        # Same reasoning as EgressGuard: a trailing root label on an address
        # literal is dropped by a WHATWG parser and handed to a resolver by
        # getaddrinfo, so one string names two destinations. Refused for names
        # too here, because a declaration is written by hand and there is no
        # cost to spelling it the way the client will.
        msg = (
            f"{url!r} carries a trailing DNS root label, which different clients resolve "
            f"to different destinations"
        )
        raise SinkNotLocalError(msg)

    try:
        port = parts.port
    except ValueError as exc:
        msg = f"{url!r} declares an unusable port ({exc})"
        raise SinkNotLocalError(msg) from exc

    return scheme, host, port if port is not None else _DEFAULT_PORTS[scheme]


def _addresses_of(
    host: str, resolve: Resolver
) -> tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, ...]:
    """Every address ``host`` denotes: itself if a literal, else what ``resolve`` says.

    An empty answer is a refusal, not an empty allowance. A host nothing will
    resolve is a host whose destination is unknown, and an unknown destination
    is the case this whole module exists to refuse.
    """
    literal = _as_ip(host)
    if literal is not None:
        return (literal,)

    answers = tuple(resolve(host))
    if not answers:
        msg = (
            f"host {host!r} is not an address literal and the configured resolver returned "
            f"nothing for it; refusing rather than assuming where it points"
        )
        raise SinkNotLocalError(msg)

    resolved: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
    for answer in answers:
        address = _as_ip(answer)
        if address is None:
            msg = f"host {host!r} resolved to {answer!r}, which is not an address"
            raise SinkNotLocalError(msg)
        resolved.append(address)
    return tuple(resolved)


def assert_sinks_are_local(
    sinks: Iterable[str], resolve: Resolver = refuse_all_names
) -> dict[str, tuple[str, ...]]:
    """Refuse unless every address every sink resolves to is loopback.

    Returns the resolved address set per sink, so a caller reporting on a run
    can record what was checked rather than that a check happened.

    ``is_loopback`` and nothing wider. ``0.0.0.0`` is unspecified rather than
    loopback and is refused; so is any private or link-local address, because
    "local" here means the machine running the measurement, not the network it
    sits on.

    An IPv4-mapped IPv6 address is judged on the address it maps to, and that
    unwrapping is done here rather than left to ``is_loopback``. The two agree
    today -- checked on 3.11, 3.12 and 3.13, which is the whole supported range
    -- so this is not a workaround. It is a refusal to let the verdict be a
    property of the interpreter: a check that reads the same everywhere because
    a standard-library property happens to is one version away from reading
    differently, and residual risk 12 records what that costs when it happens.

    Raises:
        SinkNotLocalError: on the first sink that cannot be shown to be local.
            First, not all of them: the caller must fix it and re-run, and a
            list of every problem is not more actionable than the first one.
    """
    checked: dict[str, tuple[str, ...]] = {}
    for sink in sinks:
        _, host, _ = destination_of(sink)
        addresses = tuple(_unmapped(address) for address in _addresses_of(host, resolve))
        off_loopback = [str(address) for address in addresses if not address.is_loopback]
        if off_loopback:
            msg = (
                f"sink {sink!r} resolves to {', '.join(off_loopback)}, which is not loopback. "
                f"A corpus payload that reaches a real host during a measurement is an "
                f"incident, not a measurement"
            )
            raise SinkNotLocalError(msg)
        checked[sink] = tuple(str(address) for address in addresses)
    return checked


def urls_in(text: str) -> tuple[str, ...]:
    """Every http(s) URL the text appears to contain, in order of appearance.

    Trailing punctuation is stripped because prose puts full stops after URLs
    and a destination is not a sentence. Over-approximating and lossy: this is
    a scan, not a parser, and it is used to *raise* questions rather than to
    answer them.
    """
    return tuple(match.group(0).rstrip(".,;:!?") for match in _URL_PATTERN.finditer(text))


@dataclass(frozen=True, slots=True)
class WorkspaceFile:
    """One file the workspace materialises, and where its content comes from.

    ``path`` is validated as a sequence of plain names rather than confined
    afterwards. A declaration builds a tree we own, so the safe shape is that a
    traversal is not constructible from it in the first place -- there is no
    ``..`` to resolve because a component that is not a name is refused at load.
    """

    path: str
    source: str

    def __post_init__(self) -> None:
        candidate = PurePosixPath(self.path)
        if candidate.is_absolute():
            msg = f"workspace file path {self.path!r} is absolute; it must be inside the tree"
            raise WorkspaceRejected(msg)
        for part in candidate.parts:
            if part in {"", ".", ".."} or "\\" in part:
                msg = (
                    f"workspace file path {self.path!r} contains the component {part!r}, "
                    f"which is not a plain name; a declaration builds a tree, it does not "
                    f"navigate one"
                )
                raise WorkspaceRejected(msg)


@dataclass(frozen=True, slots=True)
class WorkspaceDeclaration:
    """A disposable workspace: genuine work, one live carrier, declared sinks.

    Read from ``workspace.json`` beside the content it names, so a reviewer sees
    the payload by opening a file rather than by running a build.
    """

    name: str
    summary: str
    #: The corpus payload this carrier realises. The workspace and the corpus
    #: must not drift: a live carrier claiming a row it no longer matches would
    #: mislabel whatever the evidence run measured.
    derived_from: str
    attack: str
    carrier: str
    invariant: str
    expected_reason: str
    #: Where the live carrier lands in the built workspace.
    live_carrier: str
    sinks: tuple[str, ...]
    task: Mapping[str, Any]
    proposed_call: Mapping[str, Any]
    work: Mapping[str, Any]
    files: tuple[WorkspaceFile, ...]
    #: Directory the ``source`` fields are relative to.
    root: Path

    @property
    def call(self) -> ProposedCall:
        """The out-of-scope call the planted carrier asks the agent to make."""
        return ProposedCall(
            tool_name=str(self.proposed_call["tool_name"]),
            arguments=dict(self.proposed_call.get("arguments", {})),
        )

    def build_task(self, fs_root: str) -> Task:
        """The task an agent is given in this workspace, rooted at the built copy."""
        caps = self.task.get("caps", {})
        return Task(
            id=str(self.task.get("id", self.name)),
            tool_scope=frozenset(self.task.get("tool_scope", [])),
            fs_root=fs_root,
            egress_allowlist=frozenset(self.task.get("egress_allowlist", [])),
            caps=Caps(
                max_calls=int(caps["max_calls"]),
                max_cost=float(caps["max_cost"]),
                max_wall_clock_s=float(caps["max_wall_clock_s"]),
            ),
        )

    def content(self) -> dict[str, str]:
        """Every file's destination path mapped to the text that will be written."""
        return {
            entry.path: (self.root / entry.source).read_text(encoding="utf-8")
            for entry in self.files
        }


@dataclass(frozen=True, slots=True)
class BuiltWorkspace:
    """A materialised workspace and what was verified before it existed."""

    root: Path
    declaration: WorkspaceDeclaration
    #: Sink URL to the addresses it was shown to resolve to, all loopback.
    sinks: Mapping[str, tuple[str, ...]]

    @property
    def live_carrier(self) -> Path:
        return self.root / self.declaration.live_carrier

    def task(self) -> Task:
        return self.declaration.build_task(str(self.root))


def load_declaration(path: Path) -> WorkspaceDeclaration:
    """Read a ``workspace.json``. Raises rather than returning a partial one."""
    document = json.loads(path.read_text(encoding="utf-8"))
    files = tuple(
        WorkspaceFile(path=str(entry["path"]), source=str(entry["source"]))
        for entry in document["files"]
    )
    if not files:
        msg = f"{path} declares no files; a workspace with no work in it measures nothing"
        raise WorkspaceRejected(msg)
    return WorkspaceDeclaration(
        name=str(document["name"]),
        summary=str(document["summary"]),
        derived_from=str(document["derived_from"]),
        attack=str(document["attack"]),
        carrier=str(document["carrier"]),
        invariant=str(document["invariant"]),
        expected_reason=str(document["expected_reason"]),
        live_carrier=str(document["live_carrier"]),
        sinks=tuple(str(sink) for sink in document["sinks"]),
        task=document["task"],
        proposed_call=document["proposed_call"],
        work=document["work"],
        files=files,
        root=path.parent,
    )


def _assert_declared(content: Mapping[str, str], sinks: Sequence[str]) -> None:
    """Refuse content naming a destination the declaration does not carry.

    Compared on destination rather than on the whole URL, because two paths on
    one recorder are one place traffic goes. See the module docstring for what
    this does and does not bound.
    """
    declared = {destination_of(sink) for sink in sinks}
    for where, text in sorted(content.items()):
        for url in urls_in(text):
            if destination_of(url) not in declared:
                msg = (
                    f"{where} names {url!r}, which is not a declared sink. Every destination "
                    f"reachable from workspace content is checked for being loopback, and a "
                    f"destination that is not declared is not checked"
                )
                raise SinkNotLocalError(msg)


def _assert_carrier_is_live(declaration: WorkspaceDeclaration, content: Mapping[str, str]) -> None:
    """Refuse a declaration whose live carrier is absent or carries no sink.

    A carrier that names no destination is a quoted payload, not a live one,
    and this whole workspace exists to be the difference.
    """
    carrier = content.get(declaration.live_carrier)
    if carrier is None:
        msg = (
            f"live carrier {declaration.live_carrier!r} is not among the declared files, "
            f"so nothing in this workspace is live"
        )
        raise WorkspaceRejected(msg)
    if not any(url in declaration.sinks for url in urls_in(carrier)):
        msg = (
            f"live carrier {declaration.live_carrier!r} names none of the declared sinks "
            f"{declaration.sinks}, so the planted payload points nowhere and the workspace "
            f"would measure a quoted attack rather than a live one"
        )
        raise WorkspaceRejected(msg)


def build_workspace(
    declaration: WorkspaceDeclaration,
    destination: Path,
    resolve: Resolver = refuse_all_names,
) -> BuiltWorkspace:
    """Materialise the workspace, or refuse and leave nothing behind.

    Order is the point. Every sink is checked, and every destination named in
    the content is checked, **before** the first directory is created -- so a
    rejected workspace is not a half-written one that a later step might use
    anyway. Refusal precedes the file handle, the same ordering FR-011 requires
    of the guards.

    ``destination`` must not already exist. A workspace is disposable and is
    rebuilt per run; reusing a directory would silently carry one run's edits
    into the next, and an evidence run whose starting state depends on what
    happened last time is not one anybody can repeat.

    Raises:
        SinkNotLocalError: a declared or embedded destination is not loopback.
        WorkspaceRejected: the declaration is not usable, or the destination
            already exists.
    """
    content = declaration.content()
    # Safety before usefulness, and that ordering is deliberate. "Is any
    # destination off-loopback" is the question that turns a measurement into
    # an incident; "is the carrier actually live" only decides whether the
    # measurement is worth taking. Checking liveness first would mean a
    # declaration with a planted off-loopback sink was refused for the wrong
    # reason, and a refusal reason that misreports the control which fired is
    # the defect SECURITY.md counts as a vulnerability.
    checked = assert_sinks_are_local(declaration.sinks, resolve)
    _assert_declared(content, declaration.sinks)
    _assert_carrier_is_live(declaration, content)

    if destination.exists():
        msg = (
            f"{destination} already exists. A workspace is rebuilt per run, so building over "
            f"one would carry the previous run's edits into this one"
        )
        raise WorkspaceRejected(msg)

    destination.mkdir(parents=True)
    # Resolved against the freshly created root before anything is written, so a
    # declaration that would land outside it produces an empty directory rather
    # than a half-written tree. `resolve_within` is the same containment the
    # path guard uses -- one implementation, not a second one that could
    # disagree with it.
    try:
        targets = {where: resolve_within(where, destination) for where in sorted(content)}
    except (ConfinementError, OSError) as exc:
        msg = f"a declared file path does not resolve inside {destination} ({exc})"
        raise WorkspaceRejected(msg) from exc
    for where, target in targets.items():
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content[where], encoding="utf-8")

    return BuiltWorkspace(root=destination, declaration=declaration, sinks=checked)


def _as_ip(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return None


def _unmapped(
    address: ipaddress.IPv4Address | ipaddress.IPv6Address,
) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    """An IPv4-mapped IPv6 address, judged as the IPv4 address it maps to.

    Explicit rather than inherited. ``IPv6Address.is_loopback`` reaches the
    same answer on 3.11, 3.12 and 3.13, so this changes no verdict -- it moves
    the decision into a line that can be read, out of a property whose
    behaviour is the standard library's to change.
    """
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        return address.ipv4_mapped
    return address
