"""Agent Boundary -- a deterministic tool-call broker for LLM agents.

The broker itself lands across nodes N-05 to N-13 (see ROADMAP.md). This
package currently ships only the adversarial-suite guard, which is a control in
its own right: it is what stops the security test suite from passing by
collecting nothing.
"""

__all__ = ["__version__"]

__version__ = "0.1.0.dev0"
