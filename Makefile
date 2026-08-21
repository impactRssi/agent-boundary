# Agent Boundary -- developer gate.
#
# `make check` runs exactly what CI runs, in the same order. If it passes here
# and fails there, that divergence is a bug in this file.

.DEFAULT_GOAL := help
.PHONY: help install format format-check lint types test-unit test-adversarial \
        test-e2e test-gui coverage guards-fail-closed sast audit secrets \
        actions-pinned workflows-hardened check clean

UV ?= uv
RUN := $(UV) run

# One flag per guarded tier. Each fails the run if its tier collected fewer
# items than its floor or skipped one. Declared in
# agentboundary.testing.adversarial_guard, so this list and the code cannot
# disagree about which tiers exist -- guards-fail-closed proves each one.
TIER_GUARDS := --adversarial-guard --e2e-guard --gui-guard

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'

install: ## Create the environment and install dev dependencies
	$(UV) sync --group dev

format: ## Rewrite files to the canonical format
	$(RUN) ruff format .

format-check: ## Fail if any file is not canonically formatted
	$(RUN) ruff format --check .

lint: ## Static lint, including flake8-bandit rules
	$(RUN) ruff check .

types: ## Strict type check across src and tests
	$(RUN) mypy

test-unit: ## Unit tier
	$(RUN) pytest tests/unit

# The adversarial tier is a SEPARATE target, not a subset of the unit run.
# --adversarial-guard fails the run if the suite collected nothing or skipped a
# payload. A corpus that can silently collect zero tests is not a control.
# See ADR-0006.
test-adversarial: ## Adversarial tier, under the zero-collect / no-skip guard
	$(RUN) pytest tests/adversarial --adversarial-guard

# --extra mcp is stated here, not assumed from whatever happens to be in the
# environment. The tier drives a real MCP client against a real broker
# subprocess; without the SDK its central evidence cannot even be imported.
test-e2e: ## End-to-end tier over a real transport
	$(RUN) --extra mcp pytest tests/e2e --e2e-guard

test-gui: ## GUI tier, Playwright against the audit-trace viewer
	$(RUN) --group gui pytest tests/gui --gui-guard

# Coverage is measured over the WHOLE suite, not the unit tier alone. The
# transport, the entry point, and the handlers are exercised end to end by
# design -- measuring only unit coverage would report them as dead code and
# push someone to write unit tests that mock the boundary under test.
coverage: ## Full suite with the coverage floor enforced
	$(RUN) --group gui --extra mcp pytest tests $(TIER_GUARDS) \
		--cov=agentboundary --cov-report=term-missing

# The guards live in our own conftest, so a regression that disabled one would
# also hide itself. This asserts from outside that arming each guard against a
# tier containing nothing still fails the process. Self-referential controls
# need an external assertion; it is cheap, so it runs in the gate and not only
# in CI. `tests/unit` is the empty tier for all three by construction.
guards-fail-closed: ## Prove each tier guard still fails closed on an empty tier
	@for flag in $(TIER_GUARDS); do \
		if $(RUN) pytest tests/unit $$flag -q > /dev/null 2>&1; then \
			echo "FAIL: $$flag did not fail on an empty tier. The control is broken."; \
			exit 1; \
		fi; \
		echo "  $$flag fails closed on an empty tier."; \
	done
	@# A tier can also be emptied without disappearing: -k, -m and --deselect
	@# all run inside pytest_collection_modifyitems, where a conftest is called
	@# first. Counting there counts what was discovered, not what will run.
	@if $(RUN) pytest tests/adversarial --adversarial-guard -k no_such_test -q \
			> /dev/null 2>&1; then \
		echo "FAIL: a guard counted deselected items as evidence."; \
		exit 1; \
	fi
	@echo "  a tier emptied by a selection expression fails closed too."

sast: ## SAST over the package. Must return zero high-severity findings
	$(RUN) bandit -c pyproject.toml -r src -ll

# Audits the resolved lockfile with hashes rather than the live environment.
# The lockfile is what CI and a downstream install actually resolve, and
# --require-hashes means a mutable-artifact substitution fails the audit
# instead of passing it.
audit: ## Dependency vulnerability audit against the hash-pinned lockfile
	$(UV) export --group dev --format requirements-txt --no-emit-project > .requirements.audit.txt
	$(RUN) pip-audit --strict --require-hashes -r .requirements.audit.txt
	@rm -f .requirements.audit.txt

secrets: ## Secret scan over the full history
	@command -v gitleaks >/dev/null 2>&1 \
		|| { echo "gitleaks not installed -- FAILING CLOSED rather than skipping."; \
		     echo "  brew install gitleaks"; exit 1; }
	gitleaks detect --no-banner --redact

# A third-party action referenced by tag is code an upstream owner can swap
# after review, inside a job holding this repository's token. The pin is a
# convention until something fails the build over it, so this runs in the gate.
# GitHub validates workflow *expressions* server-side, which meant the local
# gate could not see a syntax error in one: `join(needs.*.result, " ")` uses
# double quotes, and GitHub expressions accept only single ones. That shipped
# in the first CI commit and stayed invisible until the repository was
# published, because every local check parsed the file as YAML -- which it is,
# validly -- and none parsed the expressions inside it. The very first real CI
# run failed in zero seconds with no jobs.
#
# Fails closed when actionlint is absent, same reasoning as the secret scan.
workflows-valid: ## Fail if a workflow has a syntax or expression error
	@command -v actionlint >/dev/null 2>&1 \
		|| { echo "actionlint not installed -- FAILING CLOSED rather than skipping."; \
		     echo "  brew install actionlint"; exit 1; }
	actionlint

actions-pinned: ## Fail if any workflow references an action by a movable tag
	$(RUN) python scripts/check_action_pins.py

# Every job declares its own permissions, opens with an egress audit, and
# checks out without leaving the token in .git/config for a later third-party
# step to read. Audit mode records egress; it does not bound it.
workflows-hardened: ## Fail if a CI job takes a privilege it does not need
	$(RUN) python scripts/check_workflow_hardening.py

check: format-check lint types test-unit test-adversarial test-e2e test-gui coverage guards-fail-closed sast audit secrets actions-pinned workflows-hardened ## The full gate, in CI order
	@echo
	@echo "gate passed: format, lint, types, unit, adversarial, e2e, gui, coverage, tier guards, sast, audit, secrets, action pins, workflow hardening"

clean: ## Remove build and cache artifacts
	rm -f .requirements.audit.txt
	rm -rf build dist .pytest_cache .ruff_cache .mypy_cache htmlcov .coverage coverage.xml
	@# Parallel-mode data files, one per measured child process (see pyproject).
	rm -f .coverage.*
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
