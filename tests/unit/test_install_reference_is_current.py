"""The install command a reader copies must install the release we tell them to use.

Written after finding the opposite. The README's status notice said `v0.1.0`
"should not be used: it shipped a broken MCP transport, an egress bypass, and a
defeatable test guard", and the getting-started command forty lines further down
pinned `@v0.1.0`. Two releases had shipped without the pin moving, because
nothing was watching it.

A version reference in prose goes stale silently -- there is no import to break
and no type to fail. For a security tool the failure lands on whoever followed
the instructions, which is the reader least able to notice. So it is checked.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]

#: Every document that hands a reader an installable reference.
DOCUMENTS = ("README.md", "docs/INSTALL.md")

#: `... @git+<url>@v1.2.3"` -- the pinned ref at the end of a pip/uv install line.
INSTALL_REF = re.compile(r"agent-boundary@(v\d+\.\d+\.\d+)")


def _declared_version() -> str:
    manifest = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    return str(manifest["project"]["version"])


@pytest.mark.parametrize("document", DOCUMENTS)
def test_the_documented_install_pins_the_released_version(document: str) -> None:
    text = (REPO_ROOT / document).read_text(encoding="utf-8")
    refs = set(INSTALL_REF.findall(text))
    assert refs, (
        f"{document} no longer contains a pinned install reference. If the "
        "install instructions moved, move this check with them rather than "
        "deleting it."
    )
    expected = f"v{_declared_version()}"
    assert refs == {expected}, (
        f"{document} tells a reader to install {sorted(refs)}, but pyproject "
        f"declares {expected}. Bump the documented reference with the release."
    )


def test_superseded_releases_are_never_the_documented_install() -> None:
    """The specific failure this file exists for, named so it cannot come back.

    `v0.1.0` is not merely old. It is the release the README warns against by
    name, and it was what the install command handed out for two releases.
    """
    superseded = {"v0.1.0", "v0.2.0"}
    for document in DOCUMENTS:
        text = (REPO_ROOT / document).read_text(encoding="utf-8")
        offered = set(INSTALL_REF.findall(text)) & superseded
        assert not offered, f"{document} offers a superseded release to install: {sorted(offered)}"


def test_the_check_would_notice_a_stale_pin() -> None:
    """A guard nobody has seen fail is a guard nobody has tested."""
    stale = 'uv pip install "agent-boundary[mcp] @ git+https://x/agent-boundary@v0.1.0"'
    assert INSTALL_REF.findall(stale) == ["v0.1.0"]
    assert set(INSTALL_REF.findall(stale)) & {"v0.1.0", "v0.2.0"}
