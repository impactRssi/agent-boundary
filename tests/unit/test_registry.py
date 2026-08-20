"""Per-task tool scoping (N-06, I1). Refusals first."""

from __future__ import annotations

import pytest

from agentboundary.errors import TaskConstructionError
from agentboundary.model import Caps, Irreversibility, Task, Tool
from agentboundary.registry import ScopedTools, ToolRegistry

CAPS = Caps(max_calls=5, max_cost=1.0, max_wall_clock_s=30.0)


def _task(*scope: str) -> Task:
    return Task(
        id="t-1",
        tool_scope=frozenset(scope),
        fs_root=None,
        egress_allowlist=frozenset(),
        caps=CAPS,
    )


def _registry() -> ToolRegistry:
    return ToolRegistry(
        [
            Tool(name="tickets.list", arg_schema={}, irreversibility=Irreversibility.READ),
            Tool(name="fs.read", arg_schema={}, irreversibility=Irreversibility.READ),
            Tool(name="tickets.delete", arg_schema={}),
        ]
    )


class TestConstructionFailsClosed:
    def test_scoping_an_unregistered_tool_refuses_to_construct(self) -> None:
        """FR-003. Silent narrowing would send the operator debugging the agent."""
        with pytest.raises(TaskConstructionError, match="unregistered tool"):
            _registry().scope_for(_task("tickets.list", "does.not.exist"))

    def test_the_error_names_every_missing_tool(self) -> None:
        with pytest.raises(TaskConstructionError) as excinfo:
            _registry().scope_for(_task("ghost.a", "ghost.b"))
        message = str(excinfo.value)
        assert "ghost.a" in message
        assert "ghost.b" in message

    def test_re_registering_a_name_is_an_error(self) -> None:
        """A silent overwrite could downgrade a tool's irreversibility class."""
        registry = ToolRegistry([Tool(name="x", arg_schema={})])
        with pytest.raises(ValueError, match="already registered"):
            registry.register(Tool(name="x", arg_schema={}, irreversibility=Irreversibility.READ))


class TestOutOfScopeToolsHaveNoHandle:
    def test_an_out_of_scope_tool_does_not_resolve(self) -> None:
        scoped = _registry().scope_for(_task("tickets.list"))
        assert scoped.get("tickets.delete") is None
        assert "tickets.delete" not in scoped

    def test_an_out_of_scope_tool_is_absent_from_the_model_schema(self) -> None:
        """The schema is the entire surface an injected payload can name."""
        scoped = _registry().scope_for(_task("tickets.list"))
        names = {entry["name"] for entry in scoped.model_schema()}
        assert names == {"tickets.list"}
        assert "tickets.delete" not in names
        assert "fs.read" not in names

    def test_the_registry_is_never_the_agent_surface(self) -> None:
        """Registered but unscoped tools stay invisible to the task."""
        registry = _registry()
        assert len(registry) == 3
        assert len(registry.scope_for(_task("fs.read"))) == 1

    def test_a_near_miss_name_does_not_resolve(self) -> None:
        scoped = _registry().scope_for(_task("fs.read"))
        assert scoped.get("fs.readx") is None
        assert scoped.get("fs_read") is None
        assert scoped.get("fs.rea") is None


class TestZeroToolScope:
    def test_zero_scope_constructs_and_resolves_nothing(self) -> None:
        """FR-004: legal, and every proposed call refuses."""
        scoped = _registry().scope_for(_task())
        assert len(scoped) == 0
        assert scoped.model_schema() == []
        assert scoped.get("fs.read") is None


class TestInScopeResolution:
    def test_an_in_scope_tool_resolves_to_its_registration(self) -> None:
        scoped = _registry().scope_for(_task("fs.read"))
        tool = scoped.get("fs.read")
        assert tool is not None
        assert tool.irreversibility is Irreversibility.READ

    def test_a_confusable_form_resolves_to_the_scoped_tool(self) -> None:
        """Folding closes the near-miss evasion without loosening the match."""
        scoped = _registry().scope_for(_task("fs.read"))
        assert scoped.get("\uff46s.read") is not None

    def test_scope_is_deterministic_in_order(self) -> None:
        """NFR-002: the schema handed to the model must not vary run to run."""
        registry = _registry()
        first = registry.scope_for(_task("tickets.list", "fs.read")).model_schema()
        second = registry.scope_for(_task("fs.read", "tickets.list")).model_schema()
        assert first == second


class TestScopedToolsCannotWiden:
    def test_there_is_no_way_to_add_a_tool_to_a_live_scope(self) -> None:
        """I1 as an absence: the type offers no widening operation at all."""
        scoped = _registry().scope_for(_task("fs.read"))
        assert not hasattr(scoped, "add")
        assert not hasattr(scoped, "register")

    def test_mutating_the_source_mapping_does_not_widen_the_scope(self) -> None:
        source = {"fs.read": Tool(name="fs.read", arg_schema={})}
        scoped = ScopedTools(source)
        source["tickets.delete"] = Tool(name="tickets.delete", arg_schema={})
        assert scoped.get("tickets.delete") is None

    def test_mutating_the_registry_after_scoping_does_not_widen_the_scope(self) -> None:
        registry = _registry()
        scoped = registry.scope_for(_task("fs.read"))
        registry.register(Tool(name="fs.write", arg_schema={}))
        assert scoped.get("fs.write") is None
