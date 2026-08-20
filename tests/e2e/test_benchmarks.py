"""The benchmark harness (N-23, N-24) must stay reproducible and offline."""

from __future__ import annotations

import importlib.util
import socket
import sys
from pathlib import Path
from typing import Any

import pytest

pytestmark = pytest.mark.e2e

_HARNESS = Path(__file__).resolve().parents[2] / "benchmarks" / "harness.py"


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

    def test_the_false_refusal_result_states_that_the_corpus_is_synthetic(self) -> None:
        assert "synthetic" in _load().run(iterations=20)["false_refusals"]["corpus"]

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
        assert "refusals" in benign
        assert len(benign["refusals"]) == benign["falsely_refused"]


class TestCapsFailClosed:
    def test_a_cap_stays_closed_once_reached(self) -> None:
        """A cap that let a later call through would be a rate limiter, not a bound."""
        caps = _load().run(iterations=20)["cap_behaviour"]
        for outcome in caps.values():
            assert outcome["stayed_closed"]
            assert set(outcome["refusal_reasons"]) == {"budget_exhausted"}
