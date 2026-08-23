"""The operator interface (N-45): what it refuses to be able to do.

The first two classes are the node. Everything after them is behaviour.

A refusal ledger that feeds a grant workflow is an attacker-influenced path into
the allowlist: a payload steers the agent toward a secret, the broker refuses,
the refusal is written down, and a human later approves "the things the agent
needed". That is A3 and A9 wearing a helpful interface, and the interface is
what makes it work -- a list of refusals reads like a to-do list.

So the control is a set of absences, and an absence is only a control if
something fails when it stops being absent. These tests are that something.
They assert by introspection over the parser and over module sources, because
nothing breaks at run time when a developer adds ``--approve-all``: it just
works, which is the problem.
"""

from __future__ import annotations

import argparse
import ast
import inspect
import io
import json
from collections.abc import Iterator
from pathlib import Path

import pytest

from agentboundary.leases import FileLeaseStore, Lease, LeaseError, LeaseKind, Sensitivity
from agentboundary.operator import cli as cli_module
from agentboundary.operator import grant as grant_module
from agentboundary.operator import listing as listing_module
from agentboundary.operator import refusals as refusals_module
from agentboundary.operator.cli import KINDS, SENSITIVITIES, build_parser, main
from agentboundary.operator.grant import append_lease

NOW = 1_700_000_000.0

#: Vocabulary that, appearing on the grant command line, would mean a subject
#: came from somewhere other than an operator's keyboard. Matched as substrings
#: so ``--approve-all``, ``--from-ledger``, ``--index``, ``--batch-file`` and
#: ``--yes-to-all`` are all caught by one list.
SELECTION_VOCABULARY = (
    "all",
    "any",
    "auto",
    "batch",
    "bulk",
    "each",
    "every",
    "force",
    "from-ledger",
    "index",
    "ledger",
    "many",
    "multi",
    "pick",
    "refusal",
    "select",
    "yes",
)


def _actions(parser: argparse.ArgumentParser) -> Iterator[argparse.Action]:
    yield from parser._actions


def _subparser(parser: argparse.ArgumentParser, *path: str) -> argparse.ArgumentParser:
    current = parser
    for name in path:
        found = None
        for action in _actions(current):
            if isinstance(action, argparse._SubParsersAction):
                found = action.choices[name]
        assert found is not None, f"no subcommand {name!r}"
        current = found
    return current


class TestBulkApprovalIsUnrepresentable:
    """Not "declined". There is no shape on this command line that expresses it."""

    def test_no_grant_option_names_a_selection_or_a_bulk_action(self) -> None:
        grant = _subparser(build_parser(), "lease", "grant")
        offending = {
            option
            for action in _actions(grant)
            for option in action.option_strings
            for word in SELECTION_VOCABULARY
            if word in option.lower()
        }
        assert not offending, (
            f"`lease grant` gained option(s) {sorted(offending)}. Granting names its "
            f"subject explicitly, every time: an option that selects, batches or "
            f"auto-confirms turns every refusal an attacker induced into a candidate."
        )

    def test_no_grant_option_accumulates_so_one_invocation_is_one_lease(self) -> None:
        """`append`, `extend` and `nargs='+'` are the three ways a single option
        becomes a list. All three are absent, so two subjects cannot be named."""
        grant = _subparser(build_parser(), "lease", "grant")
        for action in _actions(grant):
            assert action.nargs in (None, 0), (
                f"{action.option_strings} takes nargs={action.nargs!r}. An option that "
                f"takes more than one value is an option that grants more than one lease."
            )
            assert type(action).__name__ in {"_StoreAction", "_StoreTrueAction", "_HelpAction"}, (
                f"{action.option_strings} uses {type(action).__name__}. Only single-valued "
                f"store actions belong on a command that must grant exactly one lease."
            )

    def test_the_grant_entry_point_takes_one_subject_and_not_a_sequence(self) -> None:
        """Type-level, so a bulk caller cannot be written even bypassing argparse."""
        signature = inspect.signature(grant_module.run_grant)
        assert str(signature.parameters["subject"].annotation) == "str"
        assert not [
            name
            for name, parameter in signature.parameters.items()
            for token in ("Sequence", "list", "Iterable", "tuple", "set")
            if token in str(parameter.annotation)
        ]

    def test_every_grant_field_is_required_and_none_has_a_default(self) -> None:
        """A defaultable reason is a reason nobody writes, and a grant with no
        stated reason is indistinguishable at review time from a mistake."""
        grant = _subparser(build_parser(), "lease", "grant")
        by_option = {
            action.option_strings[0]: action for action in _actions(grant) if action.option_strings
        }
        for option in ("--store", "--kind", "--subject", "--duration", "--granted-by", "--reason"):
            assert by_option[option].required, f"{option} is not required"
            assert by_option[option].default is None, f"{option} has a default"

    @pytest.mark.parametrize(
        "argv",
        [
            ["lease", "grant", "--approve-all"],
            ["lease", "grant", "--from-ledger", "1"],
            ["lease", "grant", "--index", "1"],
            ["lease", "approve"],
            ["lease", "revoke", "--subject", "/srv/secrets"],
            ["refusals", "--approve", "1"],
            ["refusals", "--grant"],
        ],
    )
    def test_the_shapes_an_operator_might_reach_for_do_not_exist(self, argv: list[str]) -> None:
        """Including `lease revoke`: revocation is deleting a line from the store,
        because a second write path into it is the thing this design keeps to one."""
        with pytest.raises(SystemExit) as exit_info:
            build_parser().parse_args(argv)
        assert exit_info.value.code == 2

    def test_the_refusals_command_prints_nothing_that_can_be_selected(self, tmp_path: Path) -> None:
        """No row number, no id, no digest. A row with a handle is one keystroke
        from `grant 3`, and the keystroke after that is `grant --all`."""
        ledger = tmp_path / "refusals.jsonl"
        _write_refusal(ledger, subject="/etc/shadow", task_id="t-1")
        _write_refusal(ledger, subject="/etc/shadow", task_id="t-1")
        stream = io.StringIO()

        assert main(["refusals", "--ledger", str(ledger)], stream, NOW) == 0

        printed = stream.getvalue()
        assert "/etc/shadow" in printed
        assert "\n1 " not in printed
        assert "[1]" not in printed
        assert "#1" not in printed


class TestNoScopeHoldsBothARefusalAndALease:
    """The trap needs one module that can see a ledger row and build a lease."""

    @pytest.mark.parametrize(
        "module",
        [cli_module, grant_module, listing_module, refusals_module],
        ids=lambda module: module.__name__,
    )
    def test_no_operator_module_imports_both_the_ledger_and_the_leases(
        self, module: object
    ) -> None:
        imported = _imported_modules(module)
        both = {"agentboundary.ledger", "agentboundary.leases"} & imported
        assert len(both) < 2, (
            f"{getattr(module, '__name__', module)} imports {sorted(both)}. One scope that "
            f"can hold a refusal row and construct a lease is all the trap needs; the "
            f"promotion is then a single line nobody reviews."
        )

    def test_the_grant_module_cannot_name_a_refusal_at_all(self) -> None:
        imported = _imported_modules(grant_module)
        assert "agentboundary.ledger" not in imported
        assert not [name for name in imported if "ledger" in name or "refusal" in name]

    def test_the_refusals_module_cannot_name_a_lease_at_all(self) -> None:
        imported = _imported_modules(refusals_module)
        assert not [name for name in imported if "lease" in name or "rotation" in name]

    def test_no_operator_signature_accepts_a_ledger_entry(self) -> None:
        """A refusal record is never an argument to anything that grants."""
        annotations: list[str] = []
        for module in (cli_module, grant_module, listing_module):
            for name in getattr(module, "__all__", []):
                member = getattr(module, name)
                if not callable(member):
                    continue
                annotations.extend(
                    str(parameter.annotation)
                    for parameter in inspect.signature(member).parameters.values()
                )
        assert annotations, "introspection found no signatures, so it asserted nothing"
        assert not [text for text in annotations if "Ledger" in text or "Refusal" in text]

    def test_the_dispatcher_holds_no_domain_type(self) -> None:
        """`cli` moves strings from argv to a command and an exit code back. It
        cannot join a refusal to a grant because it can name neither."""
        imported = _imported_modules(cli_module, at_module_scope_only=True)
        assert imported <= {"agentboundary.operator.duration"}, (
            f"the dispatcher imports {sorted(imported)} at module scope. Keeping it free "
            f"of domain types is what makes 'promote this row' a change that has to add "
            f"an import edge to a module that has a test forbidding one."
        )


class TestTheEnumsAndTheChoicesCannotDrift:
    """The CLI repeats two closed sets as literals. This is what binds them."""

    def test_the_kinds_offered_are_exactly_the_lease_kinds(self) -> None:
        assert set(KINDS) == {member.value for member in LeaseKind}

    def test_the_classes_offered_are_exactly_the_sensitivity_classes(self) -> None:
        assert set(SENSITIVITIES) == {member.value for member in Sensitivity}

    def test_the_parser_states_no_default_classification(self) -> None:
        """FR-014's unsafe default lives in the type. Restating it here would be
        a second copy of the one decision that must not be convenient to change."""
        grant = _subparser(build_parser(), "lease", "grant")
        sensitivity = next(a for a in _actions(grant) if "--sensitivity" in a.option_strings)
        assert sensitivity.default is None


class TestGrantRefusesBeforeItWrites:
    def test_an_empty_reason_is_refused_and_writes_nothing(self, tmp_path: Path) -> None:
        store = tmp_path / "leases.jsonl"
        stream = io.StringIO()
        assert _grant(store, stream, reason="") == 2
        assert "carries no reason" in stream.getvalue()
        assert not store.exists()

    def test_a_whitespace_reason_is_refused(self, tmp_path: Path) -> None:
        store = tmp_path / "leases.jsonl"
        assert _grant(store, io.StringIO(), reason="   ") == 2
        assert not store.exists()

    def test_a_blank_grantee_is_refused(self, tmp_path: Path) -> None:
        store = tmp_path / "leases.jsonl"
        stream = io.StringIO()
        assert _grant(store, stream, granted_by=" ") == 2
        assert "must name who granted it" in stream.getvalue()
        assert not store.exists()

    def test_an_over_cap_window_is_refused_by_the_type_not_by_the_cli(self, tmp_path: Path) -> None:
        store = tmp_path / "leases.jsonl"
        stream = io.StringIO()
        assert _grant(store, stream, duration="30d") == 2
        assert "cap for class credential" in stream.getvalue()
        assert not store.exists()

    def test_a_zero_length_window_is_refused(self, tmp_path: Path) -> None:
        store = tmp_path / "leases.jsonl"
        assert _grant(store, io.StringIO(), duration="0d") == 2
        assert not store.exists()

    def test_a_malformed_duration_is_refused_before_anything_is_built(self, tmp_path: Path) -> None:
        store = tmp_path / "leases.jsonl"
        stream = io.StringIO()
        assert _grant(store, stream, duration="3") == 2
        assert "has no unit" in stream.getvalue()
        assert not store.exists()

    def test_a_relative_path_subject_is_refused(self, tmp_path: Path) -> None:
        store = tmp_path / "leases.jsonl"
        stream = io.StringIO()
        assert _grant(store, stream, subject="secrets") == 2
        assert "is relative" in stream.getvalue()
        assert not store.exists()

    def test_a_lease_over_the_filesystem_root_is_refused(self, tmp_path: Path) -> None:
        store = tmp_path / "leases.jsonl"
        stream = io.StringIO()
        assert _grant(store, stream, subject="/") == 2
        assert "removes it" in stream.getvalue()
        assert not store.exists()

    def test_an_unknown_kind_is_refused_by_the_parser(self, tmp_path: Path) -> None:
        with pytest.raises(SystemExit):
            _grant(tmp_path / "leases.jsonl", io.StringIO(), kind="everything")

    def test_a_relative_store_path_is_refused_with_a_sentence_not_a_traceback(
        self, tmp_path: Path
    ) -> None:
        """It would resolve against the working directory, which says nothing
        about whether the agent can reach it."""
        stream = io.StringIO()
        assert _grant(Path("leases.jsonl"), stream, subject=str(tmp_path / "s")) == 2
        assert "is relative" in stream.getvalue()
        assert not Path("leases.jsonl").exists()

    def test_the_append_helper_refuses_a_relative_path_too(self, tmp_path: Path) -> None:
        """The write itself is guarded, not only the command that calls it."""
        lease = Lease.granted(
            kind=LeaseKind.PATH,
            subject=str(tmp_path / "secrets"),
            granted_by="operator@example.test",
            reason="a stated reason",
            granted_at=NOW,
            duration_s=3 * 86_400.0,
        )
        with pytest.raises(LeaseError, match="is relative"):
            append_lease(Path("leases.jsonl"), lease)
        assert not Path("leases.jsonl").exists()

    def test_a_store_already_unreadable_is_not_appended_to(self, tmp_path: Path) -> None:
        """A malformed store makes every consulting call fail closed, which reads
        to an operator as 'my lease was too narrow'. Adding to it manufactures
        exactly the confusion that ends in a wider grant."""
        store = tmp_path / "leases.jsonl"
        store.write_text("{not json}\n", encoding="utf-8")
        stream = io.StringIO()

        assert _grant(store, stream) == 2

        assert "cannot be read" in stream.getvalue()
        assert "wider grant" in stream.getvalue()
        assert store.read_text(encoding="utf-8") == "{not json}\n"


class TestListingAndRefusalsFailClosedOnAMissingFile:
    """'Nothing is granted' and 'you are reading the wrong file' must differ."""

    def test_listing_a_store_that_does_not_exist_is_an_error(self, tmp_path: Path) -> None:
        stream = io.StringIO()
        code = main(["lease", "list", "--store", str(tmp_path / "absent.jsonl")], stream, NOW)
        assert code == 2
        assert "no lease store at" in stream.getvalue()
        assert "No leases granted" not in stream.getvalue()

    def test_reading_a_ledger_that_does_not_exist_is_an_error(self, tmp_path: Path) -> None:
        stream = io.StringIO()
        code = main(["refusals", "--ledger", str(tmp_path / "absent.jsonl")], stream, NOW)
        assert code == 2
        assert "no refusal ledger at" in stream.getvalue()
        assert "No refusals recorded" not in stream.getvalue()

    def test_listing_an_unreadable_store_says_calls_are_failing_closed(
        self, tmp_path: Path
    ) -> None:
        store = tmp_path / "leases.jsonl"
        store.write_text("nonsense\n", encoding="utf-8")
        stream = io.StringIO()
        assert main(["lease", "list", "--store", str(store)], stream, NOW) == 2
        assert "failing closed" in stream.getvalue()


class TestWhatAGrantActuallyDoes:
    def test_one_invocation_appends_exactly_one_lease(self, tmp_path: Path) -> None:
        store = tmp_path / "leases.jsonl"
        assert _grant(store, io.StringIO()) == 0
        assert len(store.read_text(encoding="utf-8").strip().split("\n")) == 1
        assert len(FileLeaseStore(store).leases()) == 1

    def test_a_second_grant_appends_and_does_not_rewrite(self, tmp_path: Path) -> None:
        store = tmp_path / "leases.jsonl"
        _grant(store, io.StringIO(), subject=str(tmp_path / "a"))
        first = store.read_text(encoding="utf-8")
        _grant(store, io.StringIO(), subject=str(tmp_path / "b"))
        assert store.read_text(encoding="utf-8").startswith(first)
        assert len(FileLeaseStore(store).leases()) == 2

    def test_the_store_file_is_not_world_readable(self, tmp_path: Path) -> None:
        """A lease names a path or a host an agent could reach: reconnaissance."""
        store = tmp_path / "leases.jsonl"
        _grant(store, io.StringIO())
        assert store.stat().st_mode & 0o077 == 0

    def test_an_unstated_classification_becomes_credential(self, tmp_path: Path) -> None:
        store = tmp_path / "leases.jsonl"
        _grant(store, io.StringIO())
        assert FileLeaseStore(store).leases()[0].sensitivity is Sensitivity.CREDENTIAL

    def test_a_credential_grant_says_rotation_will_be_advised(self, tmp_path: Path) -> None:
        stream = io.StringIO()
        _grant(tmp_path / "leases.jsonl", stream)
        printed = stream.getvalue()
        assert "will oblige rotation advice, unconditionally" in printed
        assert "not evidence that nothing was taken" in printed

    def test_a_routine_grant_promises_no_rotation_advice(self, tmp_path: Path) -> None:
        """Only credential-class obliges one, and the message is derived from the
        same predicate the sweep uses rather than from a second test here."""
        stream = io.StringIO()
        _grant(tmp_path / "leases.jsonl", stream, sensitivity="routine")
        assert "rotation advice" not in stream.getvalue()

    def test_the_grant_output_states_the_subject_the_window_and_the_cost(
        self, tmp_path: Path
    ) -> None:
        stream = io.StringIO()
        _grant(tmp_path / "leases.jsonl", stream, duration="3d")
        printed = stream.getvalue()
        assert "Granted 1 lease" in printed
        assert "3.00 days" in printed
        assert "the invariant it widens does not hold" in printed
        assert "delete" in printed

    def test_an_unpinned_lease_says_it_applies_to_every_task(self, tmp_path: Path) -> None:
        stream = io.StringIO()
        _grant(tmp_path / "leases.jsonl", stream)
        assert "every task in this deployment" in stream.getvalue()

    def test_a_pinned_lease_says_which_task(self, tmp_path: Path) -> None:
        stream = io.StringIO()
        _grant(tmp_path / "leases.jsonl", stream, task_id="nightly-sync")
        assert "task 'nightly-sync' only" in stream.getvalue()

    def test_the_subject_is_stored_resolved_so_the_guard_and_the_lease_agree(
        self, tmp_path: Path
    ) -> None:
        store = tmp_path / "leases.jsonl"
        target = tmp_path / "secrets"
        target.mkdir()
        _grant(store, io.StringIO(), subject=f"{target}/../secrets")
        assert FileLeaseStore(store).leases()[0].subject == str(target.resolve())


class TestListingShowsWhatCanBeRevoked:
    def test_active_and_expired_are_both_shown(self, tmp_path: Path) -> None:
        store = tmp_path / "leases.jsonl"
        _grant(store, io.StringIO(), subject=str(tmp_path / "live"), duration="3d")
        _grant(store, io.StringIO(), subject=str(tmp_path / "gone"), duration="1h")
        stream = io.StringIO()

        assert main(["lease", "list", "--store", str(store)], stream, NOW + 7_200) == 0

        printed = stream.getvalue()
        assert "live" in printed
        assert "gone" in printed
        assert "EXPIRED" in printed
        assert "remaining" in printed

    def test_the_listing_says_how_to_revoke(self, tmp_path: Path) -> None:
        store = tmp_path / "leases.jsonl"
        _grant(store, io.StringIO())
        stream = io.StringIO()
        main(["lease", "list", "--store", str(store)], stream, NOW)
        assert "delete the lease's line" in stream.getvalue()

    def test_the_listing_reports_rotation_owed_by_an_expired_credential_lease(
        self, tmp_path: Path
    ) -> None:
        store = tmp_path / "leases.jsonl"
        _grant(store, io.StringIO(), duration="1h")
        stream = io.StringIO()
        main(["lease", "list", "--store", str(store)], stream, NOW + 7_200)
        assert "Rotate every secret stored under" in stream.getvalue()

    def test_the_json_form_carries_the_notice_and_the_state(self, tmp_path: Path) -> None:
        store = tmp_path / "leases.jsonl"
        _grant(store, io.StringIO(), duration="3d")
        stream = io.StringIO()

        main(["lease", "list", "--store", str(store), "--json"], stream, NOW + 86_400)

        payload = json.loads(stream.getvalue())
        assert "does not hold for its subject" in payload["notice"]
        assert payload["leases"][0]["state"] == "active"
        assert payload["leases"][0]["remaining_days"] == pytest.approx(2.0)
        assert payload["rotation_owed"] == []

    def test_the_json_form_reports_an_expired_lease_and_the_rotation_it_owes(
        self, tmp_path: Path
    ) -> None:
        store = tmp_path / "leases.jsonl"
        _grant(store, io.StringIO(), duration="1h")
        stream = io.StringIO()

        main(["lease", "list", "--store", str(store), "--json"], stream, NOW + 86_400)

        payload = json.loads(stream.getvalue())
        assert payload["leases"][0]["state"] == "expired"
        assert payload["leases"][0]["remaining_s"] < 0
        assert len(payload["rotation_owed"]) == 1

    def test_the_json_form_reports_a_lease_that_is_not_yet_in_force(self, tmp_path: Path) -> None:
        """`pending` is not `active`. A store whose clock is ahead of the reader's
        must not read as though the widening had already happened."""
        store = tmp_path / "leases.jsonl"
        _grant(store, io.StringIO(), duration="3d")
        stream = io.StringIO()

        main(["lease", "list", "--store", str(store), "--json"], stream, NOW - 86_400)

        payload = json.loads(stream.getvalue())
        assert payload["leases"][0]["state"] == "pending"


class TestTheRefusalCaveatTravels:
    def test_the_text_output_states_what_a_row_cannot_tell_a_reviewer(self, tmp_path: Path) -> None:
        ledger = tmp_path / "refusals.jsonl"
        _write_refusal(ledger, subject="/etc/shadow", task_id="t-1")
        stream = io.StringIO()

        main(["refusals", "--ledger", str(ledger)], stream, NOW)

        printed = stream.getvalue()
        assert "cannot distinguish a legitimate workflow from a payload" in printed
        assert "typed by an operator" in printed

    def test_the_json_output_carries_the_caveat_too(self, tmp_path: Path) -> None:
        """A caveat only the human-readable form shows is one that disappears the
        first time someone pipes this into a dashboard."""
        ledger = tmp_path / "refusals.jsonl"
        _write_refusal(ledger, subject="/etc/shadow", task_id="t-1")
        stream = io.StringIO()

        main(["refusals", "--ledger", str(ledger), "--json"], stream, NOW)

        payload = json.loads(stream.getvalue())
        assert "cannot distinguish a legitimate workflow" in payload["caveat"]
        assert payload["entries"][0]["subject"] == "/etc/shadow"

    def test_the_text_output_says_granting_requires_typing_the_subject(
        self, tmp_path: Path
    ) -> None:
        ledger = tmp_path / "refusals.jsonl"
        _write_refusal(ledger, subject="/etc/shadow", task_id="t-1")
        stream = io.StringIO()
        main(["refusals", "--ledger", str(ledger)], stream, NOW)
        assert "type the subject out" in stream.getvalue()

    def test_an_empty_ledger_file_still_prints_the_caveat(self, tmp_path: Path) -> None:
        ledger = tmp_path / "refusals.jsonl"
        ledger.write_text("", encoding="utf-8")
        stream = io.StringIO()
        assert main(["refusals", "--ledger", str(ledger)], stream, NOW) == 0
        assert "not a request for permission" in stream.getvalue()


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------


def _imported_modules(module: object, *, at_module_scope_only: bool = False) -> set[str]:
    """Every ``agentboundary`` module ``module`` imports, at any scope.

    Parsed from source rather than read off ``sys.modules``, because an import
    inside a function has usually not run when this test does -- and the import
    inside a function is precisely the one a promotion path would use.
    """
    source = Path(inspect.getsourcefile(module) or "").read_text(encoding="utf-8")  # type: ignore[arg-type]
    tree = ast.parse(source)
    nodes = ast.iter_child_nodes(tree) if at_module_scope_only else ast.walk(tree)
    found: set[str] = set()
    for node in nodes:
        if isinstance(node, ast.ImportFrom) and node.module:
            found.add(node.module)
        elif isinstance(node, ast.Import):
            found.update(alias.name for alias in node.names)
    return {name for name in found if name.startswith("agentboundary")}


def _grant(
    store: Path,
    stream: io.StringIO,
    *,
    kind: str = "path",
    subject: str | None = None,
    duration: str = "3d",
    granted_by: str = "operator@example.test",
    reason: str = "nightly automation needs the credential directory",
    sensitivity: str | None = None,
    task_id: str | None = None,
) -> int:
    argv = [
        "lease",
        "grant",
        "--store",
        str(store),
        "--kind",
        kind,
        "--subject",
        str(store.parent / "secrets") if subject is None else subject,
        "--duration",
        duration,
        "--granted-by",
        granted_by,
        "--reason",
        reason,
    ]
    if sensitivity is not None:
        argv += ["--sensitivity", sensitivity]
    if task_id is not None:
        argv += ["--task-id", task_id]
    return main(argv, stream, NOW)


def _write_refusal(ledger: Path, *, subject: str, task_id: str) -> None:
    """Append a refusal in the ledger's own on-disk form."""
    record = {
        "subject_kind": "path",
        "subject": subject,
        "resolved": True,
        "reason": "path_outside_root",
        "task_id": task_id,
        "at": NOW,
    }
    with ledger.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, sort_keys=True) + "\n")
