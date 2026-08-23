"""The benchmark harness (N-23, N-24, N-37) must stay reproducible and offline."""

from __future__ import annotations

import importlib.util
import json
import socket
import sys
from pathlib import Path
from typing import Any

import pytest

pytestmark = pytest.mark.e2e

_BENCHMARKS = Path(__file__).resolve().parents[2] / "benchmarks"
_HARNESS = _BENCHMARKS / "harness.py"


def _load() -> Any:
    spec = importlib.util.spec_from_file_location("bench_harness", _HARNESS)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["bench_harness"] = module
    spec.loader.exec_module(module)
    return module


class TestOffline:
    def test_the_harness_opens_no_socket(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A number a reader cannot reproduce is a claim, not a measurement."""
        harness = _load()

        def refuse(*args: object, **kwargs: object) -> None:
            msg = "the benchmark harness attempted network I/O"
            raise AssertionError(msg)

        monkeypatch.setattr(socket, "create_connection", refuse)
        monkeypatch.setattr(socket.socket, "connect", refuse)
        results = harness.run(iterations=50)
        assert results["injection_corpus"]["attempted"] > 0


class TestReproducibility:
    def test_the_corpus_and_benign_results_do_not_vary_between_runs(self) -> None:
        harness = _load()
        first = harness.run(iterations=20)
        second = harness.run(iterations=20)
        assert first["injection_corpus"] == second["injection_corpus"]
        assert first["false_refusals"] == second["false_refusals"]
        assert first["cap_behaviour"] == second["cap_behaviour"]


class TestNumbersCarryTheirConditions:
    def test_every_result_set_names_the_conditions(self) -> None:
        harness = _load()
        results = harness.run(iterations=20)
        assert "synthetic" in results["conditions"]
        assert "offline" in results["conditions"]

    def test_the_injection_result_is_broken_down_by_carrier(self) -> None:
        """A single aggregate hides which carrier a regression came from."""
        corpus = _load().run(iterations=20)["injection_corpus"]
        assert len(corpus["by_carrier"]) >= 7

    def test_both_benign_corpora_state_that_they_are_synthetic(self) -> None:
        """The corpus is synthetic every time the rate appears, not once."""
        benign = _load().run(iterations=20)["false_refusals"]
        assert set(benign) == {"hand_written", "generated"}
        for result in benign.values():
            assert "synthetic" in result["corpus"]

    def test_the_generated_corpus_does_not_claim_independence(self) -> None:
        """N-37 narrows the caveat; it does not retire it."""
        generated = _load().run(iterations=20)["false_refusals"]["generated"]
        assert "not independent" in generated["corpus"]
        assert "repository" in generated["provenance"]

    def test_the_two_corpora_are_never_averaged_into_one_rate(self) -> None:
        """One combined figure would hide the only thing that separates them:
        who chose the cases."""
        benign = _load().run(iterations=20)["false_refusals"]
        assert "false_refusal_rate" not in benign
        assert "falsely_refused" not in benign

    def test_overhead_states_what_it_does_and_does_not_measure(self) -> None:
        measures = _load().run(iterations=20)["overhead"]["measures"]
        assert "Excludes ingest" in measures

    def test_the_headline_overhead_samples_only_authorised_calls(self) -> None:
        """The loop this replaced ran 2200 calls against a 1000-call cap, so
        1200 of its 2000 samples were budget-exhausted refusals -- a cheaper
        path, published as the per-call cost of authorisation."""
        overhead = _load().run(iterations=20)["overhead"]
        assert overhead["all_samples_authorised"] is True

    def test_the_headline_overhead_publishes_its_own_run_to_run_spread(self) -> None:
        """One mean on a laptop reads as more precise than it is."""
        overhead = _load().run(iterations=20)["overhead"]
        assert len(overhead["repeat_means_ms"]) == overhead["repeats"] >= 2
        assert overhead["repeat_mean_spread_ms"] >= 0


class TestTheHarnessDoesNotIgnoreTheLeaseControl:
    """A harness that silently drops a control its corpus exercises is measuring
    something other than what it reports, whichever way the headline comes out."""

    @staticmethod
    def _leases() -> Any:
        return _load().run(iterations=20)["injection_corpus"]["leases"]

    def test_lease_declaring_payloads_are_judged_with_their_leases(self) -> None:
        leases = self._leases()
        assert leases["judged_with_the_leases_they_declare"] is True
        assert leases["payloads_declaring_a_lease"] > 0
        assert leases["declared_lease_kinds"]

    def test_whether_the_lease_was_consulted_is_declared_not_implied(self) -> None:
        """Either give the payloads their leases or say they were measured
        without them. Leaving it undeclared is the one option ruled out."""
        leases = self._leases()
        assert set(leases) >= {
            "judged_with_the_leases_they_declare",
            "payloads_declaring_a_lease",
            "payloads_declaring_no_lease",
        }

    def test_each_lease_payload_publishes_the_counterfactual(self) -> None:
        """'A lease can only widen' is a claim about the design until the same
        payload has been run both ways and the two reasons compared."""
        for summary in self._leases()["payloads"]:
            assert summary["reason_with_its_leases"]
            assert summary["reason_with_no_lease_store"]
            assert summary["blocked_with_its_leases"] is True
            assert isinstance(summary["the_lease_changed_the_outcome"], bool)
            assert all(
                entry["state_at_lease_now"] in {"active", "expired"}
                for entry in summary["declared_leases"]
            )

    def test_the_lease_verdict_is_pinned_to_a_fixed_instant(self) -> None:
        """A result that depends on the date the harness ran is not a result."""
        leases = self._leases()
        assert "lease_now" in leases["clock"]
        for summary in leases["payloads"]:
            assert isinstance(summary["judged_at"], float)


class TestTheCostOfTheLeaseCheckIsMeasured:
    """N-43 added a lookup to two guards. An unmeasured cost is an unpublished
    regression waiting to be found by someone else."""

    @staticmethod
    def _cost() -> Any:
        return _load().run(iterations=20)["lease_check_cost"]

    def test_both_consulting_guards_are_measured_separately(self) -> None:
        guards = self._cost()["guards"]
        assert set(guards) == {"path_confinement", "egress_allowlist"}

    def test_each_delta_is_published_with_its_own_run_to_run_spread(self) -> None:
        """A delta smaller than the spread of the measurement that produced it
        is noise, and the reader has to be able to see which one it is."""
        cost = self._cost()
        for delta in cost["guards"].values():
            assert len(delta["per_repeat_delta_ms"]) == cost["repeats"] >= 2
            assert delta["delta_spread_ms"] >= 0
            assert isinstance(delta["delta_exceeds_its_own_spread"], bool)
            assert isinstance(delta["every_repeat_agrees_on_the_sign"], bool)

    def test_the_default_deployment_is_stated_next_to_the_cost(self) -> None:
        assert "no lease store is attached unless" in self._cost()["default_deployment"]

    def test_each_call_shape_states_whether_a_store_was_attached(self) -> None:
        scenarios = _load().run(iterations=20)["overhead_by_stage"]["scenarios"]
        attached = {scenario["lease_store_attached"] for scenario in scenarios.values()}
        assert attached == {True, False}


class TestUnflatteringResultsAreNotHidden:
    def test_payloads_blocked_for_the_wrong_reason_are_reported(self) -> None:
        """A payload blocked by a different control than the one under test
        inflates the headline figure, so the field exists even when empty."""
        corpus = _load().run(iterations=20)["injection_corpus"]
        assert "blocked_for_the_wrong_reason" in corpus

    def test_each_false_refusal_is_listed_individually(self) -> None:
        benign = _load().run(iterations=20)["false_refusals"]
        for result in benign.values():
            assert len(result["refusals"]) == result["falsely_refused"]
            assert sum(result["refused_by_reason"].values()) == result["falsely_refused"]

    def test_a_generated_refusal_names_the_case_and_the_reason(self) -> None:
        """A rate with no case list cannot be acted on or disputed."""
        generated = _load().run(iterations=20)["false_refusals"]["generated"]
        for refusal in generated["refusals"]:
            assert refusal["id"] and refusal["label"] and refusal["reason"]


class TestCapsFailClosed:
    def test_a_cap_stays_closed_once_reached(self) -> None:
        """A cap that let a later call through would be a rate limiter, not a bound."""
        caps = _load().run(iterations=20)["cap_behaviour"]
        for outcome in caps.values():
            assert outcome["stayed_closed"]
            assert set(outcome["refusal_reasons"]) == {"budget_exhausted"}


class TestTheGeneratedCorpusIsReproducible:
    """N-37. A corpus that cannot be regenerated is a claim, not a measurement."""

    @staticmethod
    def _generator() -> Any:
        spec = importlib.util.spec_from_file_location(
            "bench_benign_corpus", _BENCHMARKS / "benign_corpus.py"
        )
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        sys.modules["bench_benign_corpus"] = module
        spec.loader.exec_module(module)
        return module

    def test_generation_is_byte_identical_between_runs(self) -> None:
        generator = self._generator()
        first = json.dumps(generator.generate_corpus(), sort_keys=True)
        second = json.dumps(generator.generate_corpus(), sort_keys=True)
        assert first == second

    def test_the_committed_artifact_matches_a_fresh_generation(self) -> None:
        """A stale corpus on disk would mean the published rate was measured
        against something other than what a reader can regenerate."""
        generator = self._generator()
        committed = json.loads(generator.CORPUS_FILE.read_text(encoding="utf-8"))
        assert committed == generator.generate_corpus()

    def test_the_corpus_records_which_schema_keywords_it_never_exercised(self) -> None:
        """An absent keyword must not read as a covered one."""
        generator = self._generator()
        census = generator.generate_corpus()["schema_keywords"]
        assert census["declared_by_the_catalogue"]
        assert "pattern" in census["supported_but_absent_from_the_catalogue"]

    def test_no_generated_argument_carries_a_machine_specific_path(self) -> None:
        """Absolute paths are encoded, not baked in, or the corpus would only
        be reproducible on the machine that wrote it."""
        generator = self._generator()
        raw = generator.CORPUS_FILE.read_text(encoding="utf-8")
        assert "/var/folders" not in raw
        assert "/tmp/" not in raw


class TestTheOverheadIsAttributedPerGuard:
    """N-38. One aggregate cannot tell an adopter which control costs what."""

    @staticmethod
    def _stages() -> Any:
        return _load().run(iterations=20)["overhead_by_stage"]

    def test_every_pipeline_stage_is_named_in_every_call_shape(self) -> None:
        expected = {
            "scope_resolution",
            "schema_validation",
            "path_confinement",
            "egress_allowlist",
            "budget",
            "approval",
        }
        scenarios = self._stages()["scenarios"]
        assert len(scenarios) >= 3
        for scenario in scenarios.values():
            assert set(scenario["stages_ms"]) == expected

    def test_the_call_shapes_cover_a_path_a_url_and_neither(self) -> None:
        """Which control does real work depends on the arguments, so one call
        shape would attribute the cost of one deployment, not of the broker."""
        labels = " ".join(self._stages()["scenarios"])
        assert "fs.read" in labels
        assert "http.get" in labels
        assert "tickets.get" in labels

    def test_what_is_not_attributed_to_a_stage_is_published_not_absorbed(self) -> None:
        for scenario in self._stages()["scenarios"].values():
            attributed = sum(scenario["stages_ms"].values())
            assert scenario["attributed_ms"] == pytest.approx(attributed, abs=1e-4)
            assert scenario["unattributed_ms"] == pytest.approx(
                scenario["total_ms"] - attributed, abs=1e-4
            )

    def test_the_instrument_states_its_own_cost(self) -> None:
        """An attribution whose instrument's cost is unstated is not one."""
        stages = self._stages()
        assert stages["timer_pair_ms"] > 0
        assert "perf_counter" in stages["attribution_note"]
        for scenario in stages["scenarios"].values():
            assert "stages_at_the_instrument_floor" in scenario

    def test_the_breakdown_states_what_it_excludes(self) -> None:
        assert "Excludes ingest" in self._stages()["measures"]
