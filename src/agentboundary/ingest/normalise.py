"""Normalisation and active-content stripping -- invariant I2, FR-018.

Read the honesty rule before changing anything here.

**Ingest is mitigation, not proof.** It reduces the rate at which payloads
steer the model. It does not bound it, and the design does not depend on it
holding -- which is exactly why authorisation lives in the broker and not in
this file (ADR-0003). Nothing in this module may be described as *preventing*
injection. It reduces a rate.

What it does buy: content that reaches the model is in one canonical form, is
free of the constructs that execute rather than describe, and carries a record
of what was removed.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field
from typing import Final

__all__ = ["NormalisationReport", "normalise", "strip_active_content"]

#: Codepoints whose only purpose in this context is to hide or reorder text
#: from a human reader while the model still sees it. Removed, not folded:
#: there is no legitimate reason for a bidirectional override to appear in a
#: ticket description the agent is about to read.
#:
#: Written as escapes rather than literals on purpose. A source file that
#: contains real bidi controls is the Trojan Source shape, and the project's
#: own SAST flags it high-severity -- correctly. A file about hiding text must
#: not itself be able to hide text from its reviewer.
_EVASION_CODEPOINTS: Final[frozenset[str]] = frozenset(
    {
        "\u200b",  # zero width space
        "\u200c",  # zero width non-joiner
        "\u200d",  # zero width joiner
        "\u2060",  # word joiner
        "\ufeff",  # zero width no-break space / BOM
        "\u00ad",  # soft hyphen
        "\u202a",  # left-to-right embedding
        "\u202b",  # right-to-left embedding
        "\u202c",  # pop directional formatting
        "\u202d",  # left-to-right override
        "\u202e",  # right-to-left override
        "\u2066",  # left-to-right isolate
        "\u2067",  # right-to-left isolate
        "\u2068",  # first strong isolate
        "\u2069",  # pop directional isolate
    }
)

_SCRIPT_RE: Final[re.Pattern[str]] = re.compile(
    r"<\s*script\b.*?(?:</\s*script\s*>|\Z)", re.IGNORECASE | re.DOTALL
)
_STYLE_RE: Final[re.Pattern[str]] = re.compile(
    r"<\s*style\b.*?(?:</\s*style\s*>|\Z)", re.IGNORECASE | re.DOTALL
)
_IFRAME_RE: Final[re.Pattern[str]] = re.compile(
    r"<\s*i?frame\b.*?(?:</\s*i?frame\s*>|\Z)", re.IGNORECASE | re.DOTALL
)
#: Inline handlers: onclick=, onerror=, onload= and the rest of the family.
_EVENT_HANDLER_RE: Final[re.Pattern[str]] = re.compile(
    r"\son[a-z]{3,20}\s*=\s*(?:\"[^\"]*\"|'[^']*'|[^\s>]+)", re.IGNORECASE
)
#: Schemes that execute rather than locate.
_ACTIVE_URI_RE: Final[re.Pattern[str]] = re.compile(
    r"(?:javascript|vbscript|data)\s*:", re.IGNORECASE
)
#: PDF action dictionaries -- /OpenAction and /JavaScript run on open.
_PDF_ACTION_RE: Final[re.Pattern[str]] = re.compile(
    r"/(?:OpenAction|AA|JavaScript|JS|Launch|SubmitForm|ImportData)\b"
)
#: Office macro markers.
_MACRO_RE: Final[re.Pattern[str]] = re.compile(
    r"(?:vbaProject\.bin|Auto_?Open|Document_?Open|Workbook_?Open)", re.IGNORECASE
)

_CONTROL_CHARACTERS: Final[re.Pattern[str]] = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


@dataclass(frozen=True, slots=True)
class NormalisationReport:
    """What ingest changed, so the change is visible rather than invisible.

    Ingest is lossy: an agent summarising a stripped PDF is reading a different
    document from the one on disk. Recording the removals is what stops that
    from being a silent divergence (ADR-0003).
    """

    removed: tuple[str, ...] = field(default=())
    original_length: int = 0
    normalised_length: int = 0

    @property
    def modified(self) -> bool:
        return bool(self.removed) or self.original_length != self.normalised_length


def normalise(text: str) -> tuple[str, list[str]]:
    """Canonicalise encoding and unicode form, removing evasion-only codepoints.

    NFKC first, so compatibility and confusable forms collapse to one
    representation before anything is matched against them. Then the
    zero-width, bidirectional, and control characters that exist to make text
    read differently to a human than to a model.
    """
    removed: list[str] = []

    folded = unicodedata.normalize("NFKC", text)
    if folded != text:
        removed.append("unicode:nfkc-folded")

    stripped = "".join(character for character in folded if character not in _EVASION_CODEPOINTS)
    if stripped != folded:
        removed.append("unicode:evasion-codepoints")

    without_controls = _CONTROL_CHARACTERS.sub("", stripped)
    if without_controls != stripped:
        removed.append("unicode:control-characters")

    return without_controls, removed


def strip_active_content(text: str) -> tuple[str, list[str]]:
    """Remove the constructs that execute rather than describe.

    Unclosed tags are matched to end-of-input on purpose. A payload that opens
    ``<script>`` and never closes it is still a payload, and a regex requiring
    the closing tag would leave the whole body untouched -- which is the
    failure mode of every naive HTML sanitiser.

    This is a removal pass over untrusted text, not an HTML parser, and it is
    not claimed to be one. It runs *before* the broker, whose decision does not
    depend on it.
    """
    removed: list[str] = []
    result = text

    for label, pattern in (
        ("html:script", _SCRIPT_RE),
        ("html:style", _STYLE_RE),
        ("html:frame", _IFRAME_RE),
        ("html:event-handler", _EVENT_HANDLER_RE),
        ("uri:active-scheme", _ACTIVE_URI_RE),
        ("pdf:action", _PDF_ACTION_RE),
        ("office:macro", _MACRO_RE),
    ):
        replaced, count = pattern.subn("", result)
        if count:
            removed.append(f"{label}x{count}")
            result = replaced

    return result, removed
