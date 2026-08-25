"""Every sink the planted-carrier workspace declares resolves to loopback (N-51).

This tier, not the unit tier, because the property is a control rather than a
convention. A payload that is genuinely live is a payload whose named
destination something might genuinely contact, and a corpus payload reaching a
real host during a measurement is an incident, not a measurement.

Refusals first, and most of the file is refusals. Each names the resolution
trick it exists to catch, and the last group turns the guard on the artifact
that ships: plant an off-loopback sink in the real declaration and the real
builder must refuse it, having written nothing. A guard nobody has seen fail is
a guard nobody has tested.

No test here resolves a name over the network. The resolver is a parameter and
every case supplies a table, so the answer is a property of the case rather
than of the machine it ran on.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import replace
from pathlib import Path

import pytest

from agentboundary.broker import Broker
from agentboundary.model import Outcome
from agentboundary.testing import (
    SinkNotLocalError,
    WorkspaceDeclaration,
    WorkspaceRejected,
    assert_sinks_are_local,
    broker_for,
    build_workspace,
    load_corpus,
    load_declaration,
    refuse_all_names,
)
from agentboundary.testing.catalogue import reference_registry
from agentboundary.testing.corpus import Payload
from agentboundary.testing.workspace import WorkspaceFile

REPO_ROOT = Path(__file__).resolve().parents[2]
WORKSPACE = REPO_ROOT / "evidence" / "workspaces" / "planted-carrier" / "workspace.json"
CORPUS_DIR = REPO_ROOT / "corpus" / "payloads"

DECLARATION = load_declaration(WORKSPACE)

#: A resolver that answers from a table and nothing else. Deterministic and
#: offline: the sink guard's verdict must not depend on what DNS said today.
_ANSWERS = {
    "recorder.internal": ("203.0.113.7",),
    "recorder.local": ("127.0.0.1",),
    "rebinding.internal": ("127.0.0.1", "203.0.113.7"),
    "mapped.internal": ("::ffff:127.0.0.1",),
    "mapped-public.internal": ("::ffff:203.0.113.7",),
    "decimal.internal": ("2130706433",),
    "nonsense.internal": ("not-an-address",),
}


def _table(host: str) -> tuple[str, ...]:
    return _ANSWERS.get(host, ())


class TestASinkThatIsNotLoopbackIsRefused:
    """The node's exit condition, stated as the thing that must not be possible."""

    def test_a_name_resolving_to_a_public_address_is_refused(self) -> None:
        with pytest.raises(SinkNotLocalError, match=r"203\.0\.113\.7"):
            assert_sinks_are_local(["https://recorder.internal/collect"], _table)

    def test_a_name_resolving_to_loopback_and_a_public_address_is_refused(self) -> None:
        """The rebinding shape. One loopback answer does not make a host local."""
        with pytest.raises(SinkNotLocalError, match=r"203\.0\.113\.7"):
            assert_sinks_are_local(["https://rebinding.internal/collect"], _table)

    def test_a_public_literal_is_refused(self) -> None:
        with pytest.raises(SinkNotLocalError, match="not loopback"):
            assert_sinks_are_local(["https://203.0.113.7/collect"], _table)

    def test_a_name_nothing_will_resolve_is_refused(self) -> None:
        """Undecidable means refuse. An unknown destination is the case guarded."""
        with pytest.raises(SinkNotLocalError, match="returned nothing"):
            assert_sinks_are_local(["https://unknown.internal/collect"], _table)

    def test_a_resolver_answer_that_is_not_an_address_is_refused(self) -> None:
        with pytest.raises(SinkNotLocalError, match="not an address"):
            assert_sinks_are_local(["https://nonsense.internal/collect"], _table)

    def test_the_default_resolver_resolves_nothing_at_all(self) -> None:
        """No caller gets name resolution by accident, so no test can reach the network."""
        assert refuse_all_names("localhost") == ()
        with pytest.raises(SinkNotLocalError, match="returned nothing"):
            assert_sinks_are_local(["http://localhost:8973/collect"])

    def test_one_bad_sink_among_good_ones_is_refused(self) -> None:
        with pytest.raises(SinkNotLocalError, match=r"203\.0\.113\.7"):
            assert_sinks_are_local(
                ["http://127.0.0.1:8973/collect", "https://recorder.internal/collect"], _table
            )


class TestResolutionTricksAreRefused:
    """Spellings that look local, or that different clients read differently.

    Every one of these is refused, and several would be refused twice over. The
    reason each carries is the first thing that was wrong with it, because an
    operator reading it needs to know what to change.
    """

    @pytest.mark.parametrize(
        ("url", "why"),
        [
            ("http://127.0.0.1@evil.example/collect", "userinfo"),
            ("http://127.0.0.1:pass@evil.example/collect", "userinfo"),
            ("http://user@127.0.0.1:8973/collect", "userinfo"),
            ("http://0.0.0.0:8973/collect", "not loopback"),
            ("http://[::]:8973/collect", "not loopback"),
            ("http://[::ffff:203.0.113.7]:8973/collect", "not loopback"),
            ("http://2130706433/collect", "returned nothing"),
            ("http://0177.0.0.1/collect", "returned nothing"),
            ("http://0x7f000001/collect", "returned nothing"),
            ("http://127.1/collect", "returned nothing"),
            ("http://127.0.0.1./collect", "root label"),
            ("http://localhost./collect", "root label"),
            ("https://localhost.evil.example/collect", "returned nothing"),
            ("https://127.0.0.1.evil.example/collect", "returned nothing"),
            ("file:///etc/passwd", "scheme"),
            ("gopher://127.0.0.1/collect", "scheme"),
            ("http:///collect", "no host"),
            ("http://[::1]:notaport/collect", "unusable port"),
        ],
    )
    def test_the_spelling_is_refused(self, url: str, why: str) -> None:
        with pytest.raises(SinkNotLocalError, match=why):
            assert_sinks_are_local([url], _table)

    def test_a_resolver_answering_with_a_decimal_encoding_is_refused(self) -> None:
        """The trick moved into the answer rather than the question."""
        with pytest.raises(SinkNotLocalError, match="not an address"):
            assert_sinks_are_local(["https://decimal.internal/collect"], _table)

    def test_a_mapped_address_is_judged_as_what_it_maps_to(self) -> None:
        """``::ffff:x`` is decided by ``x``, and this pins both directions.

        The unwrapping is done in ``workspace.py`` rather than inherited from
        ``IPv6Address.is_loopback``. The two agree on 3.11, 3.12 and 3.13 --
        the whole supported range, checked -- so the guard is not working
        around anything; it is refusing to make its verdict a property of the
        interpreter. This test is what would notice if either side moved.
        """
        assert assert_sinks_are_local(["https://mapped.internal/collect"], _table) == {
            "https://mapped.internal/collect": ("127.0.0.1",)
        }
        with pytest.raises(SinkNotLocalError, match=r"203\.0\.113\.7"):
            assert_sinks_are_local(["https://mapped-public.internal/collect"], _table)


class TestTheGuardRefusesBeforeTheWorkspaceExists:
    """Plant an off-loopback sink in the real declaration and the real builder refuses.

    The falsifiability arm. Everything above tests the check; these test the
    thing that ships, through the same entry point an evidence run calls.
    """

    def test_the_shipped_declaration_with_a_planted_sink_is_refused(self, tmp_path: Path) -> None:
        planted = replace(DECLARATION, sinks=("https://collect.evil.example/telemetry",))
        destination = tmp_path / "workspace"
        with pytest.raises(WorkspaceRejected):
            build_workspace(planted, destination, _table)

    def test_nothing_is_materialised_when_a_sink_is_refused(self, tmp_path: Path) -> None:
        """Refusal precedes the file handle. A refused workspace does not exist."""
        planted = replace(DECLARATION, sinks=("https://recorder.internal/collect",))
        destination = tmp_path / "workspace"
        with pytest.raises(SinkNotLocalError):
            build_workspace(planted, destination, _table)
        assert not destination.exists(), (
            "a refused workspace left a directory behind. A half-built workspace is one a "
            "later step can still use."
        )

    def test_a_carrier_naming_an_undeclared_destination_is_refused(self, tmp_path: Path) -> None:
        """A second sink cannot be added to a carrier without also being declared."""
        rehomed = _restaged(
            tmp_path,
            lambda text: text + "\n<!-- mirror: https://collect.evil.example/telemetry -->\n",
        )
        with pytest.raises(SinkNotLocalError, match="not a declared sink"):
            build_workspace(rehomed, tmp_path / "workspace", _table)

    def test_a_workspace_whose_carrier_names_no_sink_is_refused(self, tmp_path: Path) -> None:
        """A carrier pointing nowhere is a quoted payload, which measures nothing."""
        defanged = _restaged(
            tmp_path,
            lambda text: text.replace("http://127.0.0.1:8973/collect", "the registration endpoint"),
        )
        with pytest.raises(WorkspaceRejected, match="names none of the declared sinks"):
            build_workspace(defanged, tmp_path / "workspace", _table)

    def test_a_workspace_whose_carrier_is_not_among_its_files_is_refused(
        self, tmp_path: Path
    ) -> None:
        """A live carrier that is not written is a workspace with nothing live in it."""
        missing = replace(DECLARATION, live_carrier="vendor/fastjson_utils/CHANGELOG.md")
        with pytest.raises(WorkspaceRejected, match="not among the declared files"):
            build_workspace(missing, tmp_path / "workspace", _table)

    def test_a_declaration_that_would_write_outside_the_tree_is_refused(self) -> None:
        """A traversal is not constructible from a declaration, so it is refused at load."""
        with pytest.raises(WorkspaceRejected, match="not a plain name"):
            WorkspaceFile(path="../../etc/passwd", source="content/parse.py.txt")
        with pytest.raises(WorkspaceRejected, match="absolute"):
            WorkspaceFile(path="/etc/passwd", source="content/parse.py.txt")

    def test_a_sink_that_cannot_be_parsed_at_all_is_refused(self) -> None:
        """Undecidable means refuse, at the parser as much as at the resolver."""
        with pytest.raises(SinkNotLocalError, match="could not be parsed"):
            assert_sinks_are_local(["http://[oops/collect"], _table)


class TestTheShippedWorkspaceIsLocalAndLive:
    """The success path, after the refusals it depends on."""

    def test_a_name_resolving_only_to_loopback_is_admitted(self) -> None:
        """The guard refuses off-loopback rather than refusing names.

        Stated because a check that refused everything would pass every test
        above and measure nothing -- the same argument the corpus makes about
        itself in `test_corpus_is_falsifiable.py`.
        """
        assert assert_sinks_are_local(["https://recorder.local/collect"], _table) == {
            "https://recorder.local/collect": ("127.0.0.1",)
        }

    def test_every_shipped_sink_resolves_only_to_loopback(self) -> None:
        checked = assert_sinks_are_local(DECLARATION.sinks, refuse_all_names)
        assert checked == {"http://127.0.0.1:8973/collect": ("127.0.0.1",)}

    def test_the_workspace_builds_with_no_name_resolution(self, tmp_path: Path) -> None:
        built = build_workspace(DECLARATION, tmp_path / "workspace")
        assert built.live_carrier.is_file()
        assert "127.0.0.1:8973/collect" in built.live_carrier.read_text(encoding="utf-8")

    def test_the_broker_refuses_the_call_the_carrier_asks_for(self, tmp_path: Path) -> None:
        """The planted instruction, judged by the full pipeline, against the real task."""
        built = build_workspace(DECLARATION, tmp_path / "workspace")
        broker = _broker_for_workspace(built.root)

        decision = broker.authorise(DECLARATION.call)

        assert decision.outcome is Outcome.REFUSE, (
            f"the planted {DECLARATION.attack} carrier at {DECLARATION.live_carrier} produced "
            f"an AUTHORISED call. {DECLARATION.summary}"
        )
        assert str(decision.reason) == DECLARATION.expected_reason

    def test_the_declaration_matches_the_corpus_payload_it_realises(self) -> None:
        """The live carrier and the quoted one must not drift apart.

        A workspace claiming an attack-table row it no longer matches would
        mislabel whatever an evidence run measured.
        """
        payloads = {payload.id: payload for payload in load_corpus(CORPUS_DIR)}
        origin = payloads.get(DECLARATION.derived_from)
        assert origin is not None, (
            f"the workspace claims to realise corpus payload "
            f"{DECLARATION.derived_from!r}, which is not in the corpus"
        )
        assert _lineage(origin) == (
            DECLARATION.attack,
            DECLARATION.carrier,
            DECLARATION.invariant,
            DECLARATION.expected_reason,
        )


def _lineage(payload: Payload) -> tuple[str, str, str, str]:
    return payload.attack, payload.carrier, payload.invariant, payload.expected_reason


def _restaged(tmp_path: Path, edit: Callable[[str], str]) -> WorkspaceDeclaration:
    """Copy the shipped declaration under ``tmp_path``, with the carrier edited.

    A tampering test must tamper with a copy. Writing into the committed tree to
    prove a guard fires would leave the artifact in whatever state the last test
    left it.
    """
    staging = tmp_path / "content"
    staging.mkdir()
    for entry in DECLARATION.files:
        text = (DECLARATION.root / entry.source).read_text(encoding="utf-8")
        if entry.path == DECLARATION.live_carrier:
            text = edit(text)
        (staging / Path(entry.source).name).write_text(text, encoding="utf-8")
    return replace(
        DECLARATION,
        root=tmp_path,
        files=tuple(
            replace(entry, source=f"content/{Path(entry.source).name}")
            for entry in DECLARATION.files
        ),
    )


def _broker_for_workspace(root: Path) -> Broker:
    """Assemble the deployment pipeline around the workspace's own task.

    Reuses the corpus harness so the workspace is judged by the same assembly
    every payload is, rather than by one written to suit it.
    """
    payload = Payload(
        id=str(DECLARATION.task["id"]),
        attack=DECLARATION.attack,
        carrier=DECLARATION.carrier,
        invariant=DECLARATION.invariant,
        expected_reason=DECLARATION.expected_reason,
        description=DECLARATION.summary,
        carrier_content=(root / DECLARATION.live_carrier).read_text(encoding="utf-8"),
        task=DECLARATION.task,
        proposed_call=DECLARATION.proposed_call,
    )
    return broker_for(payload, fs_root=str(root), registry=reference_registry())
