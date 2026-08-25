"""The session surface cannot be given a native handle (N-50, I1).

Absence first. The property this node claims is not "a native tool call was
refused" -- that is the call-time-filter shape ``ADR-0002`` rejects, and a test
asserting it would document the wrong property. The property is that no
:class:`SessionSpec` naming a native handle can be constructed at all, so the
tests that matter here are the ones where construction fails and the ones where
the surface is asserted to be exactly the broker's listing.

Nothing in this module needs an SDK, a model or the network.
:meth:`SessionSpec.sdk_options` returns plain data precisely so that the values
carrying the property stay assertable without any of the three.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from agentboundary.runner.session import (
    NATIVE_TOOL_FAMILIES,
    NO_BUILTIN_TOOLS,
    BrokeredServerSpec,
    SessionSpec,
    SessionSurfaceError,
    qualify,
    session_spec,
)

SERVER = "agentboundary"

#: A representative brokered listing: the names `python -m agentboundary`
#: returns for a task scoping these three tools.
BROKERED = ("fs.read", "tickets.comment", "tickets.get")


def a_spec(tools: tuple[str, ...] = BROKERED) -> SessionSpec:
    return session_spec(
        server_name=SERVER,
        command="/usr/bin/python3",
        args=("-m", "agentboundary", "--task", "task.json"),
        brokered_tools=tools,
    )


class TestANativeHandleCannotBeRepresented:
    """The load-bearing class. Construction refuses; nothing filters at call time."""

    @pytest.mark.parametrize("native", sorted(NATIVE_TOOL_FAMILIES))
    def test_a_built_in_tool_name_cannot_enter_a_surface(self, native: str) -> None:
        """Every native family, one test each. Not 'Bash is refused' -- 'Bash is
        not a value this type accepts'."""
        with pytest.raises(SessionSurfaceError) as caught:
            SessionSpec(
                server=BrokeredServerSpec(name=SERVER, command="python3"),
                tools=(native,),
            )
        assert native in str(caught.value)

    def test_the_refusal_says_why_rather_than_only_that(self) -> None:
        """An operator triages on this string; it has to name the invariant."""
        with pytest.raises(SessionSurfaceError) as caught:
            SessionSpec(server=BrokeredServerSpec(name=SERVER, command="python3"), tools=("Bash",))
        message = str(caught.value)
        assert "cannot be given" in message
        assert "I1" in message and "ADR-0002" in message

    def test_a_tool_from_another_mcp_server_cannot_enter_the_surface(self) -> None:
        """The check is not 'is it an MCP tool' but 'is it *this broker's* tool'.

        A second MCP server is a second route to an effect, which is the same
        defect as a native handle wearing a different name.
        """
        with pytest.raises(SessionSurfaceError):
            SessionSpec(
                server=BrokeredServerSpec(name=SERVER, command="python3"),
                tools=("mcp__someone_elses_server__fs.write",),
            )

    def test_a_name_that_merely_looks_qualified_is_refused(self) -> None:
        """Exact prefix, not 'contains mcp'. A near-miss must not resolve."""
        for near_miss in ("mcp__agentboundaryX__fs.read", "MCP__agentboundary__fs.read"):
            with pytest.raises(SessionSurfaceError):
                SessionSpec(
                    server=BrokeredServerSpec(name=SERVER, command="python3"),
                    tools=(near_miss,),
                )

    def test_a_bare_prefix_with_no_tool_behind_it_is_refused(self) -> None:
        with pytest.raises(SessionSurfaceError, match="no tool behind it"):
            SessionSpec(
                server=BrokeredServerSpec(name=SERVER, command="python3"),
                tools=(f"mcp__{SERVER}__",),
            )

    def test_a_repeated_tool_is_refused(self) -> None:
        """Two spellings of one handle make the rendered surface order-dependent."""
        name = qualify(SERVER, "fs.read")
        with pytest.raises(SessionSurfaceError, match="repeats a tool"):
            SessionSpec(
                server=BrokeredServerSpec(name=SERVER, command="python3"), tools=(name, name)
            )

    def test_there_is_no_field_through_which_a_builtin_could_be_requested(self) -> None:
        """The structural claim, asserted structurally.

        If a future change adds a settable field for built-in tools, this fails
        -- which is the point. The absence of the field *is* the control; the
        prefix check above only stops one arriving through ``tools``.
        """
        fields = set(SessionSpec.__dataclass_fields__)
        assert fields == {"server", "tools", "cwd"}
        assert a_spec().builtin_tools == ()

    def test_the_built_in_set_cannot_be_assigned_to(self) -> None:
        """It is a read-only property, so there is no field to set.

        The exception type is deliberately loose. A frozen ``slots=True``
        dataclass rebuilds the class, which leaves ``__setattr__`` raising
        ``TypeError`` for a property where it raises ``FrozenInstanceError``
        for a field. Pinning either one would be pinning a CPython quirk; what
        this node needs is that the assignment does not take, so that is what
        is asserted -- including the value afterwards.
        """
        spec = a_spec()
        with pytest.raises((AttributeError, TypeError)):
            spec.builtin_tools = ("Bash",)  # type: ignore[misc]
        assert spec.builtin_tools == ()

    def test_a_spec_is_immutable(self) -> None:
        """A surface that can be widened after it is checked was never checked."""
        spec = a_spec()
        before = spec.tools
        with pytest.raises((AttributeError, TypeError)):
            spec.tools = (qualify(SERVER, "fs.write"),)  # type: ignore[misc]
        assert spec.tools == before


class TestAnAmbiguousServerNameIsRefused:
    """The prefix test is a proof only while the name space cannot overlap."""

    def test_a_server_name_containing_the_separator_is_refused(self) -> None:
        with pytest.raises(SessionSurfaceError, match="separator"):
            BrokeredServerSpec(name="agent__boundary", command="python3")

    def test_an_empty_server_name_is_refused(self) -> None:
        with pytest.raises(SessionSurfaceError):
            BrokeredServerSpec(name="", command="python3")


class TestTheSurfaceIsExactlyTheBrokersListing:
    def test_every_tool_on_the_surface_is_a_brokered_one(self) -> None:
        assert a_spec().tools == tuple(qualify(SERVER, name) for name in sorted(BROKERED))

    def test_no_native_family_appears_anywhere_on_the_surface(self) -> None:
        surface = a_spec().tools
        assert not (set(surface) & NATIVE_TOOL_FAMILIES)

    def test_a_task_scoping_nothing_yields_a_surface_of_nothing(self) -> None:
        """Fail closed: an empty listing is an empty session, not a default one."""
        spec = a_spec(tools=())
        assert spec.tools == ()
        assert spec.builtin_tools == ()
        assert spec.sdk_options()["tools"] == []

    def test_the_surface_does_not_depend_on_listing_order(self) -> None:
        """NFR-002. The same task and the same listing give the same spec."""
        forward = a_spec(tools=BROKERED)
        backward = a_spec(tools=tuple(reversed(BROKERED)))
        assert forward == backward
        assert forward.render() == backward.render()


class TestTheSdkOptionsCarryTheProperty:
    """Asserted as data. No SDK, no model, no network -- see ADR-0009."""

    def test_the_built_in_tool_set_is_the_empty_list_not_a_default(self) -> None:
        """`[]` means no built-in tools; `None` means all of them. The node is
        that distinction, so it is asserted as a distinction."""
        options = a_spec().sdk_options()
        assert options["tools"] == []
        assert options["tools"] is not None
        assert list(NO_BUILTIN_TOOLS) == []

    def test_no_native_handle_is_named_anywhere_in_the_options(self) -> None:
        """Absence across the whole configuration, not only the tool list."""
        rendered = repr(a_spec().sdk_options())
        for native in NATIVE_TOOL_FAMILIES:
            assert native not in rendered, f"{native} reachable through session configuration"

    def test_the_allowed_list_is_the_brokered_surface_and_nothing_else(self) -> None:
        """`allowed_tools` auto-approves; per the SDK it does *not* restrict.

        So it is asserted to match the surface rather than to define it. If it
        ever disagreed with ``tools``, the surface would still be the one
        ``tools`` produced -- which is why the property is not tested here.
        """
        options = a_spec().sdk_options()
        assert options["allowed_tools"] == list(a_spec().tools)

    def test_nothing_is_blocked_by_name(self) -> None:
        """A blocklist would mean the capability was reachable and we declined it."""
        assert a_spec().sdk_options()["disallowed_tools"] == []

    def test_an_unapproved_call_is_denied_rather_than_prompted_for(self) -> None:
        """A prompt is a process waiting on a human who is not there."""
        assert a_spec().sdk_options()["permission_mode"] == "dontAsk"

    def test_only_the_brokered_server_is_configured(self) -> None:
        options = a_spec().sdk_options()
        assert set(options["mcp_servers"]) == {SERVER}
        assert options["mcp_servers"][SERVER]["command"] == "/usr/bin/python3"
        assert options["mcp_servers"][SERVER]["args"][:2] == ["-m", "agentboundary"]

    @pytest.mark.parametrize(
        ("option", "expected"),
        [
            # Every one of these widens the surface when left to a default:
            # a discovered server, a settings file, a plugin, a subagent, a
            # skill, or an extra readable directory.
            ("strict_mcp_config", True),
            ("setting_sources", []),
            ("plugins", []),
            ("agents", None),
            ("skills", None),
            ("add_dirs", []),
        ],
    )
    def test_a_surface_widening_option_is_set_explicitly(
        self, option: str, expected: object
    ) -> None:
        assert a_spec().sdk_options()[option] == expected

    def test_the_working_directory_is_passed_through_when_given(self) -> None:
        spec = session_spec(
            server_name=SERVER,
            command="python3",
            args=(),
            brokered_tools=BROKERED,
            cwd=Path("/tmp/workspace"),
        )
        assert spec.sdk_options()["cwd"] == "/tmp/workspace"


class TestTheOperatorCanSeeTheSurface:
    def test_the_rendering_says_no_native_handle_exists(self) -> None:
        rendered = a_spec().render()
        assert "(none: no native handle exists)" in rendered

    def test_the_rendering_lists_every_brokered_tool(self) -> None:
        rendered = a_spec().render()
        for name in BROKERED:
            assert qualify(SERVER, name) in rendered

    def test_the_rendering_of_an_empty_scope_says_so_rather_than_looking_broken(self) -> None:
        assert "(nothing: the task scopes no tool)" in a_spec(tools=()).render()


class TestTheEnvironmentIsCarriedWhenGiven:
    def test_an_env_is_passed_to_the_spawned_broker(self) -> None:
        spec = session_spec(
            server_name=SERVER,
            command="python3",
            args=(),
            brokered_tools=(),
            env={"PYTHONHASHSEED": "0"},
        )
        assert spec.sdk_options()["mcp_servers"][SERVER]["env"] == {"PYTHONHASHSEED": "0"}

    def test_no_env_key_is_emitted_when_none_is_given(self) -> None:
        """Absent, not empty. An empty env would blank the child's environment."""
        assert "env" not in a_spec().sdk_options()["mcp_servers"][SERVER]
