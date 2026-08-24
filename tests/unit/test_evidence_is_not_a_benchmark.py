"""The two clauses of ADR-0009 that a file can be checked against (N-49).

An ADR that only describes a rule is a comment. These are the parts of that
decision a later change could erode one helpful pull request at a time -- a
model id added to the reproducible results because it seemed like useful
context, a convenience dependency added to the authorisation path because it
was only a small one -- so they are asserted rather than reviewed for.

The clauses that are *not* checkable here (an evidence run reports every
sample; no evidence figure is averaged into a benchmark one) belong to an
artifact that does not exist yet. They are N-52's to carry.
"""

from __future__ import annotations

import ast
import json
import sys
import tomllib
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
PACKAGE_ROOT = REPO_ROOT / "src" / "agentboundary"

#: The optional MCP adapter is the one place a third-party import is expected.
#: It is an extra (`pip install agent-boundary[mcp]`), not a runtime dependency,
#: and the broker it serves does not import it back.
OPTIONAL_SUBPACKAGES = ("mcp",)

#: Fields whose presence would mean a model produced part of this file. Matched
#: as whole keys except for ``model``, which is matched as a substring so that
#: `model_id`, `model_version` and `judge_model` are all caught.
MODEL_DERIVED_KEYS = frozenset(
    {
        "temperature",
        "top_p",
        "top_k",
        "max_tokens",
        "prompt",
        "completion",
        "transcript",
        "provider",
        "api_key",
    }
)


def _authorisation_path_modules() -> list[Path]:
    return sorted(
        path
        for path in PACKAGE_ROOT.rglob("*.py")
        if not any(part in OPTIONAL_SUBPACKAGES for part in path.relative_to(PACKAGE_ROOT).parts)
    )


def _imported_roots(module: Path) -> set[str]:
    """Top-level package names this module imports, relative imports excluded."""
    roots: set[str] = set()
    for node in ast.walk(ast.parse(module.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Import):
            roots.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            roots.add(node.module.split(".")[0])
    return roots


def _keys_of(payload: object) -> set[str]:
    """Every mapping key anywhere in a decoded JSON document."""
    found: set[str] = set()
    if isinstance(payload, dict):
        found |= set(payload)
        for value in payload.values():
            found |= _keys_of(value)
    elif isinstance(payload, list):
        for value in payload:
            found |= _keys_of(value)
    return found


class TestTheAuthorisationPathIsDependencyFree:
    """ADR-0009 §6. The decision path is small enough to read, and stays that way.

    The claim appears in the README, in the constitution, and in the pitch. It
    was, until this test, a convention -- and a convention is what an evidence
    harness needing an agent SDK is most likely to quietly cost.
    """

    def test_the_declared_runtime_dependency_list_is_empty(self) -> None:
        manifest = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
        declared = manifest["project"]["dependencies"]
        assert declared == [], (
            f"`[project] dependencies` must stay empty; found {declared}. "
            "An agent SDK, or anything else the evidence harness needs, belongs "
            "in [project.optional-dependencies] -- see ADR-0009 §6."
        )

    def test_no_module_on_the_authorisation_path_imports_a_third_party_package(self) -> None:
        stdlib = set(sys.stdlib_module_names)
        offenders: dict[str, set[str]] = {}
        for module in _authorisation_path_modules():
            foreign = {
                root
                for root in _imported_roots(module)
                if root not in stdlib and root != "agentboundary"
            }
            if foreign:
                offenders[str(module.relative_to(REPO_ROOT))] = foreign
        assert not offenders, (
            f"third-party imports outside the optional adapter: {offenders}. "
            "An empty dependency list means nothing if the code imports anyway."
        )

    def test_the_check_would_notice_a_third_party_import(self, tmp_path: Path) -> None:
        """The guard above passes on a clean tree; prove it can fail."""
        planted = tmp_path / "planted.py"
        planted.write_text("import requests\nfrom agentboundary import model\n", encoding="utf-8")
        roots = _imported_roots(planted)
        assert "requests" in roots
        assert "requests" not in set(sys.stdlib_module_names)


class TestTheReproducibleResultsStayModelFree:
    """ADR-0009 §1. What makes 46/46 worth citing is that a reader can re-derive it."""

    def test_results_json_carries_no_model_derived_field(self) -> None:
        results = REPO_ROOT / "benchmarks" / "results.json"
        keys = _keys_of(json.loads(results.read_text(encoding="utf-8")))
        named = {key for key in keys if key.lower() in MODEL_DERIVED_KEYS}
        modelled = {key for key in keys if "model" in key.lower()}
        assert not (named | modelled), (
            f"`benchmarks/results.json` gained model-derived fields: {sorted(named | modelled)}. "
            "A model-in-the-loop figure belongs under evidence/ -- see ADR-0009 §1."
        )

    @pytest.mark.parametrize("planted", ["model_id", "judge_model", "temperature"])
    def test_the_check_would_notice_one(self, planted: str) -> None:
        """A guard nobody has seen fail is a guard nobody has tested."""
        keys = _keys_of({"injection_corpus": {"attempted": 46, planted: "x"}})
        named = {key for key in keys if key.lower() in MODEL_DERIVED_KEYS}
        modelled = {key for key in keys if "model" in key.lower()}
        assert named | modelled == {planted}
