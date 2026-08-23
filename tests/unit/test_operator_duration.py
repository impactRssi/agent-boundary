"""Duration parsing for ``lease grant`` (N-45).

The refusals come first, and there are more of them than acceptances, which is
the right ratio for a grammar sitting in front of a control: every spelling that
could make a window mean something other than it looks like it means has to be
refused here or refused by :class:`~agentboundary.leases.Lease` -- and the last
class in this file is the one that proves the second half of that sentence,
because a parser that quietly enforced the caps itself would be a second opinion
on a rule it does not own.
"""

from __future__ import annotations

import pytest

from agentboundary.leases import MAX_DURATION_S, Lease, LeaseError, LeaseKind, Sensitivity
from agentboundary.operator.duration import SECONDS_PER_UNIT, DurationError, parse_duration


class TestTheGrammarRefusesAmbiguity:
    def test_a_bare_number_has_no_unit_and_is_refused(self) -> None:
        """Three seconds and three days are both plausible readings of '3'."""
        with pytest.raises(DurationError, match="has no unit"):
            parse_duration("3")

    def test_the_refusal_for_a_bare_number_names_the_forms_that_work(self) -> None:
        with pytest.raises(DurationError, match="3d, 12h, 90m, 30s"):
            parse_duration("259200")

    @pytest.mark.parametrize("text", ["1d12h", "3d 4h", "1h30m"])
    def test_a_compound_duration_is_refused(self, text: str) -> None:
        """A grammar with addition in it invites 1d1d."""
        with pytest.raises(DurationError, match="not <number><unit>"):
            parse_duration(text)

    @pytest.mark.parametrize("text", ["+3d", "-3d", "1e5s", "1_000s", "0x10s", ".5d"])
    def test_a_number_that_does_not_look_like_what_it_means_is_refused(self, text: str) -> None:
        with pytest.raises(DurationError, match="not <number><unit>"):
            parse_duration(text)

    def test_a_non_ascii_digit_is_refused(self) -> None:
        """Confusable input is refused by the grammar, not normalised into it."""
        with pytest.raises(DurationError, match="not <number><unit>"):
            parse_duration("٣d")  # ARABIC-INDIC DIGIT THREE

    @pytest.mark.parametrize("text", ["infd", "nand", "foreverd", "d", "3", ""])
    def test_no_word_parses_as_a_duration(self, text: str) -> None:
        with pytest.raises(DurationError):
            parse_duration(text)

    @pytest.mark.parametrize("text", ["3w", "3y", "3M", "3D"])
    def test_a_unit_the_grammar_does_not_offer_is_refused(self, text: str) -> None:
        """Uppercase included: 3D is not 3d, and guessing which was meant is not
        a decision a parser in front of a control gets to make."""
        with pytest.raises(DurationError):
            parse_duration(text)

    def test_the_unit_refusal_lists_the_units_that_exist(self) -> None:
        with pytest.raises(DurationError, match="units are d, h, m, s"):
            parse_duration("3w")

    def test_surrounding_whitespace_is_tolerated_but_embedded_text_is_not(self) -> None:
        """A duration arriving from a file or a heredoc keeps its line ending, so
        stripping it is right; anything past the unit is not whitespace and is
        refused, ``\\Z`` rather than ``$`` so a newline cannot end the match early."""
        assert parse_duration("3d\n") == 3 * 86_400.0
        for text in ("3d\n4h", "3d rm -rf /", "3d;12h"):
            with pytest.raises(DurationError):
                parse_duration(text)


class TestTheParserDoesNotOwnThePolicy:
    """The caps live in ``leases.py``. This parser must not know them."""

    def test_zero_parses_and_is_refused_by_the_lease_type(self) -> None:
        """The grammar accepts 0d; the type is what says a lease must authorise
        something. Splitting it the other way would put the rule in two places."""
        assert parse_duration("0d") == 0.0
        with pytest.raises(LeaseError, match="not a finite positive number"):
            _lease(parse_duration("0d"))

    def test_an_over_cap_window_parses_and_is_refused_by_the_lease_type(self) -> None:
        seconds = parse_duration("30d")
        assert seconds == 30 * 86_400.0
        with pytest.raises(LeaseError, match="cap for class credential"):
            _lease(seconds)

    def test_a_number_so_large_it_overflows_to_infinity_is_refused_by_the_type(self) -> None:
        """`float` of a 400-digit integer is `inf`. The grammar has no opinion;
        the type rejects every spelling of 'forever', including this one."""
        seconds = parse_duration("1" * 400 + "d")
        assert seconds == float("inf")
        with pytest.raises(LeaseError, match="not a finite positive number"):
            _lease(seconds)

    def test_the_parser_module_does_not_reference_the_caps(self) -> None:
        import inspect
        from pathlib import Path

        from agentboundary.operator import duration as duration_module

        source = Path(inspect.getsourcefile(duration_module) or "").read_text(encoding="utf-8")
        assert "from agentboundary" not in source, (
            "the duration parser imported something from the package. It parses a "
            "grammar; the moment it can see MAX_DURATION_S there are two answers to "
            "'how long may this lease run' and one of them is the one an operator sees."
        )

    def test_the_longest_offered_unit_still_cannot_express_the_widest_cap_twice(self) -> None:
        """A sanity check on the unit table, not on the caps: one day is the
        coarsest unit, so no single-unit duration can be written that the type
        would not also have to check."""
        assert max(SECONDS_PER_UNIT.values()) == 86_400.0
        assert parse_duration("60d") > max(MAX_DURATION_S.values())


class TestTheFormsThatWork:
    @pytest.mark.parametrize(
        ("text", "seconds"),
        [
            ("3d", 259_200.0),
            ("12h", 43_200.0),
            ("90m", 5_400.0),
            ("30s", 30.0),
            ("1.5h", 5_400.0),
            ("  3d  ", 259_200.0),
        ],
    )
    def test_a_human_duration_becomes_seconds(self, text: str, seconds: float) -> None:
        assert parse_duration(text) == seconds

    def test_a_parsed_duration_reaches_the_lease_unchanged(self) -> None:
        lease = _lease(parse_duration("3d"))
        assert lease.duration_s == 259_200.0
        assert lease.expires_at == lease.granted_at + 259_200.0


def _lease(duration_s: float) -> Lease:
    return Lease.granted(
        kind=LeaseKind.PATH,
        subject="/srv/secrets",
        granted_by="operator@example.test",
        reason="an automation needs it",
        granted_at=1_700_000_000.0,
        duration_s=duration_s,
        sensitivity=Sensitivity.CREDENTIAL,
    )
