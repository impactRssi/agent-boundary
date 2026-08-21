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
