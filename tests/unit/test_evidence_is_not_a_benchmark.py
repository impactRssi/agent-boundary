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

#: Subpackages where a third-party import is expected. Each is an optional
#: extra -- `agent-boundary[mcp]`, `agent-boundary[runner]` -- never a runtime
#: dependency, and the broker they serve does not import them back.
#:
#: `runner` joined `mcp` at N-50, which needs an agent SDK. Excluding a whole
#: subpackage is a coarse lever, so it is paired with
#: :data:`OPTIONAL_ADAPTER_MODULES` below: the exclusion buys the two binding
#: modules a third-party import and buys nothing else. Without that pairing,
#: `agentboundary/runner/session.py` -- where the session's tool surface is
#: actually decided -- would have left the guarded path, and that module is
#: exactly the kind of thing this guard exists for.
OPTIONAL_SUBPACKAGES = ("mcp", "runner")

#: Within those subpackages, the only modules that may actually carry a
#: third-party import. Everything else under them is held to the same rule as
#: the authorisation path.
#:
#: Adding a name here is a visible diff and needs the argument the subpackage
#: needed. It is also how `mcp/server.py` -- which assembles the guard pipeline
#: in `build_broker` and had been unguarded since the exclusion was written --
#: comes back under the check.
OPTIONAL_ADAPTER_MODULES = frozenset(
    {
        "mcp/stdio.py",
        "runner/claude.py",
        "runner/discovery.py",
    }
)

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


def _is_optional(path: Path) -> bool:
    return any(part in OPTIONAL_SUBPACKAGES for part in path.relative_to(PACKAGE_ROOT).parts)


def _authorisation_path_modules() -> list[Path]:
    return sorted(path for path in PACKAGE_ROOT.rglob("*.py") if not _is_optional(path))


def _optional_subpackage_modules() -> list[Path]:
    """Modules inside an excluded subpackage that are not a declared binding."""
    return sorted(
        path
        for path in PACKAGE_ROOT.rglob("*.py")
        if _is_optional(path)
        and path.relative_to(PACKAGE_ROOT).as_posix() not in OPTIONAL_ADAPTER_MODULES
    )


def _foreign_imports(module: Path) -> set[str]:
    stdlib = set(sys.stdlib_module_names)
    return {
        root for root in _imported_roots(module) if root not in stdlib and root != "agentboundary"
    }


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
        offenders: dict[str, set[str]] = {}
        for module in _authorisation_path_modules():
            foreign = _foreign_imports(module)
            if foreign:
                offenders[str(module.relative_to(REPO_ROOT))] = foreign
        assert not offenders, (
            f"third-party imports outside the optional adapters: {offenders}. "
            "An empty dependency list means nothing if the code imports anyway."
        )

    def test_only_the_declared_binding_modules_import_one_inside_an_optional_subpackage(
        self,
    ) -> None:
        """Excluding a subpackage must not exclude everything inside it.

        `mcp/` and `runner/` each hold a thin binding that needs its SDK, and
        alongside it the code that decides something -- `mcp/server.py`
        assembles the guard pipeline, `runner/session.py` decides the session's
        tool surface. Those are guarded here, so widening the coarse exclusion
        at N-50 did not quietly widen what it permits.
        """
        offenders: dict[str, set[str]] = {}
        for module in _optional_subpackage_modules():
            foreign = _foreign_imports(module)
            if foreign:
                offenders[str(module.relative_to(REPO_ROOT))] = foreign
        assert not offenders, (
            f"third-party imports in an optional subpackage outside its declared "
            f"binding modules: {offenders}. Either move the import into one of "
            f"{sorted(OPTIONAL_ADAPTER_MODULES)}, or add the module to that set and "
            f"say why -- see ADR-0009 §6."
        )

    def test_every_declared_binding_module_exists(self) -> None:
        """A pin naming a deleted file silently stops guarding anything."""
        missing = sorted(
            name for name in OPTIONAL_ADAPTER_MODULES if not (PACKAGE_ROOT / name).is_file()
        )
        assert not missing, f"OPTIONAL_ADAPTER_MODULES names files that do not exist: {missing}"

    def test_the_surface_deciding_modules_are_guarded_rather_than_excluded(self) -> None:
        """Name them, so the coverage cannot be lost by renaming a directory."""
        guarded = {
            path.relative_to(PACKAGE_ROOT).as_posix() for path in _authorisation_path_modules()
        }
        guarded |= {
            path.relative_to(PACKAGE_ROOT).as_posix() for path in _optional_subpackage_modules()
        }
        for module in ("mcp/server.py", "runner/session.py", "runner/__main__.py"):
            assert module in guarded, f"{module} decides something and must stay guarded"

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
