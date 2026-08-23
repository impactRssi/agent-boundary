"""Duration parsing for ``lease grant``. Grammar only -- never policy.

An operator says "three days", not "259200". This module turns the first into
the second and does nothing else.

**What it deliberately does not know.** The per-class maximum windows live in
:data:`agentboundary.leases.MAX_DURATION_S`, and this module does not import
them, compare against them, or mention them. A parser that re-implemented the
caps would be a second opinion on the same question, and the two would drift --
at which point the one an operator sees first is the one that is wrong. So
``0d`` parses to ``0.0`` and ``9999d`` parses to a large finite number; both are
then refused by :class:`~agentboundary.leases.Lease`, which is the type that
owns the rule.

**What the grammar refuses, and why that is not policy.**

* A bare number. ``--duration 3`` is ambiguous between three seconds and three
  days, and a duration whose unit a reader has to guess is a duration an
  operator will get wrong in the permissive direction exactly once.
* A compound form such as ``1d12h``. One unit, one number: a grammar with
  addition in it invites ``1d1d``.
* Anything with a sign, an exponent, a separator, or a non-ASCII digit --
  ``+3d``, ``1e5s``, ``1_000s``, ``٣d``. These are the spellings that make a
  number mean something other than it looks like it means.
* ``inf``, ``nan``, and every other word. There is no spelling of "forever"
  here, and :class:`~agentboundary.leases.Lease` rejects the float forms too,
  so the property is held twice by two different mechanisms.
"""

from __future__ import annotations

import re
from typing import Final

__all__ = ["SECONDS_PER_UNIT", "DurationError", "parse_duration"]


class DurationError(ValueError):
    """A duration was not written in a form this grammar accepts.

    A ``ValueError`` rather than a ``BrokerError``: nothing here decides
    anything about authorisation. It is a spelling mistake at a command line,
    and the command exits without touching the lease store.
    """


#: One unit, one number. Anchored with ``\A``/``\Z`` rather than ``^``/``$``,
#: because ``$`` also matches before a trailing newline -- and a duration
#: arriving from a file or a shell heredoc would then parse with the newline
#: silently discarded.
_DURATION: Final[re.Pattern[str]] = re.compile(r"\A(?P<value>[0-9]+(?:\.[0-9]+)?)(?P<unit>[a-z])\Z")

#: Seconds per accepted unit. Deliberately short: weeks and months are not here,
#: because both are longer than every window this system grants and offering
#: them would invite an operator to write one and be refused later by a rule
#: they cannot see from the command line.
SECONDS_PER_UNIT: Final[dict[str, float]] = {
    "s": 1.0,
    "m": 60.0,
    "h": 3_600.0,
    "d": 86_400.0,
}

_FORMS: Final[str] = "3d, 12h, 90m, 30s"


def parse_duration(text: str) -> float:
    """Return the number of seconds ``text`` names.

    The result is handed straight to
    :meth:`agentboundary.leases.Lease.granted`, which is what refuses a window
    that is not positive, not finite, or over the cap for its sensitivity class.

    Raises:
        DurationError: ``text`` is not ``<number><unit>`` with the unit one of
            ``s``, ``m``, ``h``, ``d``.
    """
    candidate = text.strip()
    if not candidate:
        msg = f"a lease needs a duration; write one of {_FORMS}"
        raise DurationError(msg)

    matched = _DURATION.match(candidate)
    if matched is None:
        if candidate.isascii() and candidate.replace(".", "", 1).isdigit():
            msg = (
                f"duration {text!r} has no unit. Three seconds and three days are both "
                f"plausible readings of {candidate!r}, and a window whose unit a reader "
                f"has to guess is one an operator gets wrong in the permissive "
                f"direction. Write one of {_FORMS}."
            )
            raise DurationError(msg)
        msg = (
            f"duration {text!r} is not <number><unit>. One number and one unit, no sign, "
            f"no exponent, no separator, no compound form: write one of {_FORMS}."
        )
        raise DurationError(msg)

    unit = matched.group("unit")
    if unit not in SECONDS_PER_UNIT:
        permitted = ", ".join(sorted(SECONDS_PER_UNIT))
        msg = (
            f"duration {text!r} uses unit {unit!r}. The units are {permitted}; a longer "
            f"one is not offered because no lease runs that long. Write one of {_FORMS}."
        )
        raise DurationError(msg)

    # float() cannot fail here: the group is ASCII digits with at most one dot.
    return float(matched.group("value")) * SECONDS_PER_UNIT[unit]
