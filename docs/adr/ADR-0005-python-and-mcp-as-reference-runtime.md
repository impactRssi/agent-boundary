# ADR-0005 — Python and MCP as the reference runtime

- **Status:** Accepted
- **Date:** 2026-08-20
- **Upholds:** none directly; constrains how I1–I4 are implemented

## Context

The broker has to be reachable by an agent runtime someone actually uses,
otherwise the control is a paper. Two questions: which language, and which
integration surface.

The integration surface matters more than the language. A broker wired in as a
library is one import away from being bypassed — a developer who calls the tool
handler directly has removed the control without noticing. A broker that sits
behind a process boundary and speaks a protocol cannot be bypassed by accident.

## Decision

**Python 3.11+** for the reference implementation, and **MCP (Model Context
Protocol)** as the primary integration surface.

The broker ships as an installable package *and* as an MCP server. The MCP
server is the supported integration; the library is what the server is built
from and what tests exercise directly.

Core dependencies stay at zero. The standard library covers what the
authorisation path needs, and every dependency added to that path is code an
attacker's payload eventually reaches.

## Consequences

**Accepted.**

- The process boundary makes the control hard to bypass by accident. Tools live
  behind the broker, not beside it.
- MCP is where agent tooling is consolidating, so a drop-in config reaches
  several runtimes rather than one.
- Python matches the security tooling the gate depends on — bandit, pip-audit,
  semgrep — and matches the ecosystem most agent integrations are written in.
- `pathlib` and `os.path.realpath` give the symlink-resolving primitives I4
  needs, and `ruff`'s `PTH` rules keep path handling on that path rather than
  on string manipulation.
- Zero runtime dependencies means the audit surface of the authorisation path
  is our own code. It also means writing more of it ourselves, including JSON
  Schema validation. Accepted deliberately: schema validation is *on* the
  authorisation path, and a validator with a large transitive tree is a poor
  trade there.
- Python is slower than a compiled alternative. Per-call overhead is published
  in milliseconds (NFR-001) so a reader can decide whether that matters. If it
  does, the design ports — the invariants are not language-specific.
- A TypeScript adapter is not ruled out. It is deferred rather than rejected,
  and would be a second surface over the same broker, never a second broker.

**Rejected: library-only distribution.** Simplest to build and easiest to
bypass. The whole argument of this project is structural over procedural, and a
library that a developer can route around is a procedural control.
