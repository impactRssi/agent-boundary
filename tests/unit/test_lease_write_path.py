"""The broker process has no way to write a lease (N-45).

:class:`~agentboundary.leases.LeaseStore` has no ``grant``, for the same reason
:class:`~agentboundary.approval.ApprovalStore` has none: if the store could mint
a lease, anything holding a reference to it -- including code reachable from a
steered agent loop -- could mint one too. ``tests/unit/test_leases.py`` asserts
that the class exposes no such method.

This file asserts the wider property that node N-45 has to keep true once a
write path exists somewhere in the project. There is exactly one, in
:mod:`agentboundary.operator.grant`, and the claim is that the serving side
cannot reach it: not "does not call it", but does not import it, at any scope,
transitively.

Static analysis here; ``tests/e2e/test_operator_interface.py`` makes the same
assertion dynamically against a real serving subprocess, because a static
import graph is a claim about source and the process image is the thing that
matters.
"""

from __future__ import annotations

import ast
import importlib
import inspect
from pathlib import Path

import pytest

from agentboundary import leases as leases_module
from agentboundary.leases import FileLeaseStore, InMemoryLeaseStore, LeaseStore

PACKAGE = Path(inspect.getsourcefile(leases_module) or "").parent

#: The modules a serving process assembles a broker out of. If the write path is
#: unreachable from every one of them, it is unreachable from the authorisation
#: path -- whatever transport is bolted on later.
SERVING_ROOTS = (
    "agentboundary.broker",
    "agentboundary.guards",
    "agentboundary.confinement",
    "agentboundary.leases",
    "agentboundary.ledger",
    "agentboundary.rotation",
    "agentboundary.mcp.server",
    "agentboundary.mcp.stdio",
    "agentboundary.handlers",
    "agentboundary.viewer.server",
)

#: Every way a Python module writes bytes to a path. Present in ``grant.py``,
#: absent from ``leases.py``: the read side and the write side of a lease store
#: are different files on purpose.
WRITE_PRIMITIVES = (
    "O_WRONLY",
    "O_RDWR",
    "O_APPEND",
    "O_CREAT",
    "write_text",
    "write_bytes",
    "os.write",
    "writelines",
    "shutil.copy",
    "shutil.move",
    "os.rename",
    "os.replace",
)


def _source(module_name: str) -> str:
    module = importlib.import_module(module_name)
    return Path(inspect.getsourcefile(module) or "").read_text(encoding="utf-8")


def _imports(module_name: str) -> set[str]:
    """Every ``agentboundary`` module imported, at any scope.

    Any scope, deliberately. A lazy import inside a function is still a module
    the process loads the moment that function runs, and "we only import it in
    the branch that needs it" is exactly how a write path gets into an image
    nobody expected it in.
    """
    tree = ast.parse(_source(module_name))
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            found.add(node.module)
        elif isinstance(node, ast.Import):
            found.update(alias.name for alias in node.names)
    return {name for name in found if name.startswith("agentboundary")}


def _reachable(roots: tuple[str, ...]) -> set[str]:
    seen: set[str] = set()
    queue = list(roots)
    while queue:
        name = queue.pop()
        if name in seen:
            continue
        seen.add(name)
        try:
            queue.extend(_imports(name))
        except (ImportError, TypeError, OSError):  # pragma: no cover - namespace packages
            continue
    return seen


class TestTheServingSideCannotReachTheWritePath:
    def test_the_write_path_is_not_reachable_from_any_serving_module(self) -> None:
        reachable = _reachable(SERVING_ROOTS)
        offending = {name for name in reachable if name.startswith("agentboundary.operator")}
        assert not offending, (
            f"a serving module reaches {sorted(offending)}. agentboundary.operator.grant "
            f"holds the only code that writes a lease; an import edge from the broker to "
            f"it puts lease creation inside the process a steered loop runs in."
        )

    def test_the_entry_point_imports_it_only_inside_the_dispatch_branch(self) -> None:
        """`__main__` is allowed to reach it -- it is the dispatcher -- but only
        lazily, so a serving invocation never loads the module at all."""
        tree = ast.parse(_source("agentboundary.__main__"))
        module_scope: set[str] = set()
        for node in ast.iter_child_nodes(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                module_scope.add(node.module)
            elif isinstance(node, ast.Import):
                module_scope.update(alias.name for alias in node.names)
        assert not [name for name in module_scope if name.startswith("agentboundary.operator")]
        assert "agentboundary.operator.cli" in _imports("agentboundary.__main__"), (
            "the dispatch branch no longer imports the operator CLI, so this test is "
            "asserting the absence of something that was never there."
        )

    def test_the_write_path_exists_where_this_test_says_it_does(self) -> None:
        """Guards the tests above against becoming vacuous."""
        source = _source("agentboundary.operator.grant")
        assert any(primitive in source for primitive in WRITE_PRIMITIVES)

    def test_the_lease_module_contains_no_write_primitive(self) -> None:
        source = _source("agentboundary.leases")
        offending = [primitive for primitive in WRITE_PRIMITIVES if primitive in source]
        assert not offending, (
            f"agentboundary.leases gained {offending}. The module the broker imports must "
            f"be able to read a lease store and nothing else."
        )

    @pytest.mark.parametrize(
        "store_type",
        [LeaseStore, InMemoryLeaseStore, FileLeaseStore],
        ids=lambda store_type: store_type.__name__,
    )
    def test_no_store_type_exposes_a_method_that_writes(self, store_type: type) -> None:
        offending = {
            name
            for name in dir(store_type)
            if not name.startswith("_")
            for word in ("grant", "add", "append", "write", "save", "record", "extend", "renew")
            if word in name.lower()
        }
        assert not offending, f"{store_type.__name__} exposes {sorted(offending)}"

    def test_the_store_the_broker_holds_cannot_be_written_through_its_return_value(self) -> None:
        """`leases()` hands back a tuple, so a caller cannot append through it."""
        store = InMemoryLeaseStore()
        assert isinstance(store.leases(), tuple)
        assert isinstance(store.expired(0.0), tuple)


class TestEveryModuleInThePackageIsAccountedFor:
    def test_no_module_outside_the_operator_package_writes_a_lease_store(self) -> None:
        """A second write path is the failure this whole shape exists to prevent.

        Scoped to the primitives that create or open a file for writing, and
        applied to every module in the package except the operator package and
        the two append-only sinks that are meant to have one -- the audit trace,
        the refusal ledger and the rotation advisories all write, and all of them
        write records the agent's own effects produce rather than permission.
        """
        permitted = {
            "agentboundary/audit.py",
            "agentboundary/ledger.py",
            "agentboundary/rotation.py",
            "agentboundary/handlers.py",
        }
        offenders: list[str] = []
        for path in sorted(PACKAGE.rglob("*.py")):
            relative = str(path.relative_to(PACKAGE.parent))
            if relative in permitted or relative.startswith("agentboundary/operator/"):
                continue
            source = path.read_text(encoding="utf-8")
            if "Lease" in source and any(
                primitive in source for primitive in ("O_WRONLY", "write_text", "write_bytes")
            ):
                offenders.append(relative)
        assert not offenders, (
            f"{offenders} name a Lease and open something for writing. Lease creation "
            f"lives in one module, outside the broker's import graph, on purpose."
        )
