"""Placeholder payload proving the adversarial tier is wired and discoverable.

This is not an attack. It exists so that the tier collects a non-zero count
before the corpus lands at node N-17, and so that a regression in discovery is
caught by the guard rather than by nobody.

It is deleted in N-17, when real payloads make it redundant.
"""

from __future__ import annotations


def test_adversarial_tier_is_discovered() -> None:
    """If this does not run, the guard should be failing the build."""
    assert True
