# Installation

Three ways in, depending on what you want. Pick one — they are not steps in a
sequence.

| I want to… | Go to |
|---|---|
| See the control refuse a real attack, in 60 seconds | [Run the demo](#1-run-the-demo) |
| Put the broker in front of my own agent | [Use it](#2-use-it) |
| Change the code, and run the gate that guards it | [Develop on it](#3-develop-on-it) |

Every command below has been run against a clean clone. If one fails for you,
that is a bug — open an issue rather than working around it.

---

## Prerequisites

| Tool | Needed for | Install |
|---|---|---|
| **Python 3.11+** | Everything | [python.org](https://www.python.org/downloads/) or your package manager |
| **[uv](https://docs.astral.sh/uv/)** | Everything | `curl -LsSf https://astral.sh/uv/install.sh \| sh` |
| **gitleaks** | The secret-scan step of the gate | `brew install gitleaks` |
| **A browser** | The GUI test tier | Installed by `uv run playwright install chromium` |

The project itself has **zero runtime dependencies** — a clean install pulls
exactly one package, itself. Everything in the table above is build-time or
test-time only. That is a deliberate property of the authorisation path, not an
accident: every dependency on that path is code an attacker's payload
eventually reaches ([ADR-0005](adr/ADR-0005-python-and-mcp-as-reference-runtime.md)).

---

## 1. Run the demo

The fastest way to see what this does.

```bash
git clone https://github.com/impactRssi/agent-boundary
cd agent-boundary
uv sync --group dev
uv run python examples/support_triage.py
```

An agent triages a support ticket. The ticket was written by an attacker who
has no session, no API key, and no way to address the agent — they filed a
ticket, which is the whole capability the threat model grants them.

You should see the agent's legitimate work authorised, and every steered call
refused with the reason that refused it:

```
AUTHORISED     legitimate: read the runbook
AUTHORISED     legitimate: read the ticket
REFUSED [path_outside_root]     steered by the ticket: read /etc/passwd
REFUSED [approval_mismatch]     steered by the ticket: publish it
REFUSED [tool_not_in_scope]     out of scope entirely
AUTHORISED     approved comment
```

No network is touched and nothing outside a temporary directory is written.

### Look at the trace in a browser

```python
from agentboundary.audit import MemoryAuditSink
from agentboundary.viewer import serve

audit = MemoryAuditSink()
# ... run a task with `audit` as the sink; see examples/support_triage.py ...
serve(audit.records())  # http://127.0.0.1:8765
```

Read-only, on localhost, with no authentication — a trace carries validated
arguments, so put it behind whatever you already use.

---

## 2. Use it

> **Not on PyPI yet.** Install from the repository until it is; the README's
> `pip install` line will change when that stops being true.

```bash
uv pip install "agent-boundary[mcp] @ git+https://github.com/impactRssi/agent-boundary@v0.1.0"
```

The `[mcp]` extra pulls the MCP SDK. Without it you get the library and the
broker; with it you get the stdio server, which is the supported way to use
this. A broker imported as a library is one import away from being bypassed: a
developer who calls a tool handler directly has removed the control, and
nothing in the diff says so.

### Write a task file

The task file **is** the security configuration — scope, filesystem root,
egress allowlist, caps. Treat it as a reviewed artifact, not as flags someone
improvises at a prompt.

```json
{
  "id": "support-triage",
  "tool_scope": ["fs.read", "tickets.list", "tickets.get"],
  "fs_root": "./workspace",
  "egress_allowlist": [],
  "caps": { "max_calls": 25, "max_cost": 25.0, "max_wall_clock_s": 120.0 }
}
```

Every omission fails closed. A missing `egress_allowlist` means **no** egress,
not unrestricted egress. A missing cap is an error rather than a generous
default: an operator who forgot to set a limit has not decided there should be
none.

### Check it before serving

```bash
python -m agentboundary --task task.json --dry-run
```

Prints the resolved scope, root, allowlist, and caps, then exits. Run it after
every edit — the scope you meant and the scope you wrote are not always the
same, and this is the cheapest place to find that out.

### Point your agent runtime at it

`.mcp.json`, or `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "agent-boundary": {
      "command": "python",
      "args": ["-m", "agentboundary",
               "--task", "/etc/agent-boundary/task.json",
               "--approvals", "/etc/agent-boundary/approvals.json",
               "--audit", "/var/log/agent-boundary/trace.jsonl"]
    }
  }
}
```

Two placements carry security weight, and both are outside `fs_root`:

- **`--approvals`** — an approval store the agent can write to is not out of
  band, and the approval gate is the only thing standing in front of
  irreversible effects.
- **`--audit`** — a trace the agent can rewrite is not a trace.

A full worked configuration is in
[`examples/dropin/`](../examples/dropin/README.md).

---

## 3. Develop on it

### Full setup

```bash
git clone https://github.com/impactRssi/agent-boundary
cd agent-boundary
uv sync --group dev --group gui --extra mcp
uv run playwright install chromium
make check
```

`make check` is the whole gate, in the order CI runs it. It should end with:

```
gate passed: format, lint, types, unit, adversarial, e2e, gui, coverage, sast, audit, secrets
```

If it passes locally and fails in CI, that divergence is a bug in the
`Makefile`, not a local quirk to work around.

### What each install option unlocks

`uv sync --group dev` alone is **not** enough for the full gate — `mypy` type
checks the MCP adapter and the GUI tier, so both need to be present:

| Command | Unlocks |
|---|---|
| `uv sync --group dev` | format, lint, unit, adversarial, sast, audit |
| `+ --extra mcp` | `make types` (the MCP adapter is type-checked) |
| `+ --group gui` | `make test-gui` — plus `uv run playwright install chromium` |
| `brew install gitleaks` | `make secrets` |

The secret scan **fails closed when gitleaks is absent** rather than skipping.
A control that silently does nothing when its tool is missing is the failure
mode this whole project argues against, so the `Makefile` refuses to model it.

### Individual targets

```bash
make help              # every target, with a one-line description

make test-unit         # unit tier
make test-adversarial  # the 36 injection payloads, under the zero-collect guard
make test-e2e          # the assembled system
make test-gui          # Playwright against the audit viewer, in a real browser
make coverage          # whole suite with the coverage floor enforced

make sast              # bandit; must return zero high-severity findings
make audit             # pip-audit against the hash-pinned lockfile
make secrets           # gitleaks over the full history
```

### Reproduce the published numbers

```bash
uv run python benchmarks/harness.py
```

Offline, no network, single process. Every figure is emitted with the
conditions it was measured under. Read the caveat on the false-refusal rate in
[`benchmarks/README.md`](../benchmarks/README.md) before quoting that one — the
benign corpus is synthetic and written by the same author as the controls.

---

## Troubleshooting

**`make check` fails at `types` with `Cannot find implementation or library
stub for module named "mcp"`**
You ran `uv sync --group dev` without `--extra mcp`. Use the full setup command
above.

**`make check` fails at `secrets` with `gitleaks not installed`**
Install it (`brew install gitleaks`). The target fails rather than skipping, by
design — see above.

**`make test-gui` fails with a missing browser**
Run `uv run playwright install chromium`.

**`pip install agent-boundary` cannot find the package**
It is not published yet. Use the git URL in [Use it](#2-use-it).

**A tool call is refused and you believe it should not be**
That is the control's cost, and it is measured and published rather than
hidden. Check the refusal reason against
[`docs/SPEC.md` §3](SPEC.md#refusal-reasons) — the reason names which check
fired. If the task's scope, root, allowlist, or caps genuinely permit the call
and it was still refused, that is a bug: see [`SECURITY.md`](../SECURITY.md).
