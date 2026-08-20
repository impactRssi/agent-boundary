"""Test package marker.

Present so each tier is an importable package: without it the per-tier conftest
modules all resolve to the bare name "conftest", which breaks type checking and
makes shared harness types unimportable across tiers.
"""
