"""Tool registry and per-task scoping -- invariant I1.

The shape of this module is the argument. A global registry with a call-time
permission check means the capability was reachable and we chose not to use it;
one missing check is then a hole. Here, scope is resolved **at construction
time**: an out-of-scope tool is absent from the dispatch table and absent from
the schema the model is shown. There is no handle to name and nothing to
jailbreak toward (ADR-0002, FR-001 to FR-005).
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator, Mapping
from typing import Any

from agentboundary.errors import TaskConstructionError
from agentboundary.model import Task, Tool, normalise_tool_name

__all__ = ["ScopedTools", "ToolRegistry"]


class ToolRegistry:
    """Everything the deployment *could* offer. Never handed to a model.

    A registry is a deployment-wide catalogue. What an agent sees is always a
    :class:`ScopedTools` built from a task, never this.
    """

    def __init__(self, tools: Iterable[Tool] = ()) -> None:
        self._tools: dict[str, Tool] = {}
        for tool in tools:
            self.register(tool)

    def register(self, tool: Tool) -> None:
        """Add a tool. Re-registering a name is an error, not an overwrite.

        Silent replacement would let a later import swap the irreversibility
        class or the schema of an existing tool -- a capability downgrade that
        no diff of the call site would reveal.
        """
        if tool.name in self._tools:
            msg = (
                f"tool {tool.name!r} is already registered. Re-registration would "
                f"silently replace its schema and irreversibility class."
            )
            raise ValueError(msg)
        self._tools[tool.name] = tool

    def __contains__(self, name: object) -> bool:
        return isinstance(name, str) and normalise_tool_name(name) in self._tools

    def __len__(self) -> int:
        return len(self._tools)

    def __iter__(self) -> Iterator[Tool]:
        return iter(self._tools.values())

    def names(self) -> frozenset[str]:
        return frozenset(self._tools)

    def scope_for(self, task: Task) -> ScopedTools:
        """Build the only tool surface this task will ever have.

        Fails closed when the scope names something unregistered (FR-003). It
        must not silently narrow: a task that asked for four tools and quietly
        received three would run, half-crippled, and the operator would debug
        the agent instead of the configuration.
        """
        missing = sorted(name for name in task.tool_scope if name not in self._tools)
        if missing:
            msg = (
                f"task {task.id!r} scopes unregistered tool(s): {', '.join(missing)}. "
                f"Refusing to construct rather than silently narrowing the scope."
            )
            raise TaskConstructionError(msg)
        return ScopedTools({name: self._tools[name] for name in sorted(task.tool_scope)})


class ScopedTools:
    """The tools a task can reach. An out-of-scope tool is simply not here.

    Immutable by construction: there is no ``add``. Widening a live task's
    surface is not an operation this type supports, which is invariant I1
    stated as an absence rather than as a check.
    """

    __slots__ = ("_tools",)

    def __init__(self, tools: Mapping[str, Tool]) -> None:
        self._tools: dict[str, Tool] = dict(tools)

    def __contains__(self, name: object) -> bool:
        return isinstance(name, str) and normalise_tool_name(name) in self._tools

    def __len__(self) -> int:
        return len(self._tools)

    def __iter__(self) -> Iterator[Tool]:
        return iter(self._tools.values())

    def get(self, name: str) -> Tool | None:
        """Resolve a proposed name. Exact match on the normalised form only.

        Returns ``None`` rather than raising: an unresolvable name is an
        ordinary refusal the broker records, not an exceptional condition.
        """
        return self._tools.get(normalise_tool_name(name))

    def names(self) -> frozenset[str]:
        return frozenset(self._tools)

    def model_schema(self) -> list[dict[str, Any]]:
        """The tool list handed to the model.

        This is the whole attack surface an injected payload can name. It
        contains the task's tools and nothing else -- not the deployment's
        catalogue, not a filtered view of it with the rest still dispatchable.
        """
        return [
            {
                "name": tool.name,
                "description": tool.description,
                "input_schema": dict(tool.arg_schema),
            }
            for tool in self._tools.values()
        ]
