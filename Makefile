# Agent Boundary -- developer gate.
#
# `make check` runs exactly what CI runs, in the same order. If it passes here
# and fails there, that divergence is a bug in this file.

.DEFAULT_GOAL := help
.PHONY: help install format format-check lint types test-unit test-adversarial \
        test-e2e test-gui coverage sast audit secrets check clean

UV ?= uv
RUN := $(UV) run

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

test-e2e: ## End-to-end tier over a real transport
	$(RUN) pytest tests/e2e

test-gui: ## GUI tier, Playwright against the audit-trace viewer
	$(RUN) pytest tests/gui -m gui

# Coverage is measured over the WHOLE suite, not the unit tier alone. The
# transport, the entry point, and the handlers are exercised end to end by
# design -- measuring only unit coverage would report them as dead code and
# push someone to write unit tests that mock the boundary under test.
coverage: ## Full suite with the coverage floor enforced
	$(RUN) pytest tests --adversarial-guard --cov=agentboundary --cov-report=term-missing

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

check: format-check lint types test-unit test-adversarial test-e2e coverage sast audit secrets ## The full gate, in CI order
	@echo
	@echo "gate passed: format, lint, types, unit, adversarial, e2e, coverage, sast, audit, secrets"

clean: ## Remove build and cache artifacts
	rm -f .requirements.audit.txt
	rm -rf build dist .pytest_cache .ruff_cache .mypy_cache htmlcov .coverage coverage.xml
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
