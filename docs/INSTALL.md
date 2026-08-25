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
uv pip install "agent-boundary[mcp] @ git+https://github.com/impactRssi/agent-boundary@v0.4.0"
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

### Size `max_wall_clock_s` for the span, not for the work

`max_wall_clock_s` bounds the time from task construction to the call being
decided. That span includes model latency and any time a human spends reading
between turns. It is **not** a sum of how long the calls themselves took.

The distinction matters once, and sharply. A batch task issuing twenty calls
back to back may finish inside 120 s. The same twenty calls issued by an agent
a human is watching can span half an hour, nearly all of it spent waiting on
the model or on the person — and the cap will fire with the task having spent
under a second inside the broker. The refusal is correct, the task is dead, and
nothing the operator configured says that is what they asked for.

| Deployment | Starting point |
|---|---|
| Batch or CI, no human in the loop | 120 s |
| Interactive session, human reading between turns | 1800 s |

Both are numbers we chose to be survivable for their shape of task, not figures
derived from a measurement, and both are starting points to narrow against what
your task actually does rather than defaults to adopt.

Bounding the span rather than the call time is deliberate. What needs a limit is
how long a steered agent may keep acting, and an agent idling between two cheap
calls is still able to act; a cap over call durations would leave that
unbounded. If your task legitimately runs long, raise the number and say why in
the file — do not reach for a cap that measures something easier to satisfy.

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

### Or let the runner build the session for you

Pointing your own runtime at the broker leaves one thing to you, and it is the
thing that decides whether any of this is worth anything: **the brokered tools
have to be the only tools.** A session that reaches the broker for `fs.read`
while holding a native `Bash` handle has not been bounded — the effect the
broker refused was reachable by another route, and the refusal proved nothing.
That is [ADR-0002](adr/ADR-0002-per-task-tool-scoping.md)'s argument turned on
the harness rather than on the broker.

The runner is that session, built correctly:

```bash
uv pip install "agent-boundary[runner] @ git+https://github.com/impactRssi/agent-boundary@v0.4.0"
export ANTHROPIC_API_KEY=...

python -m agentboundary.runner --task task.json --dry-run
```

`--dry-run` spawns the broker, completes a real MCP handshake, reads the tool
listing and prints the session's whole surface — then exits. It calls no model
and costs nothing:

```
agent-boundary runner: server 'agentboundary'
  spawn:    /usr/bin/python3 -m agentboundary --task task.json --audit .audit/trace.jsonl
  builtin:  (none: no native handle exists)
  brokered: mcp__agentboundary__fs.read, mcp__agentboundary__tickets.get
  settings: (none: strict MCP config, no user/project/local sources)
```

Drop `--dry-run` and add `--prompt` to actually run it. Without one of the two
it refuses to start rather than billing you for an empty session.

What the runner sets, and why each one matters:

| Setting | Effect |
|---|---|
| `tools=[]` | **The load-bearing one.** No built-in tool exists in the session. `[]` means none; `None` would mean all of them |
| `strict_mcp_config=True` | A `.mcp.json` sitting in the working directory cannot add a second server |
| `setting_sources=[]` | No user, project or local settings — those carry skills, permissions and further servers |
| `allowed_tools` | Auto-approval only. Per the SDK it does **not** restrict the tool set, so it is derived from the broker's listing and is never the control |
| `permission_mode="dontAsk"` | Anything not pre-approved is denied rather than prompted for. A prompt in a non-interactive run is a process waiting on a human who is not there |

The tool list is read from the broker over the transport, never from your task
file. A tool lease that widened the scope is therefore included, and there is
no second derivation of "what this session may reach" to drift out of step.

Authentication is by **API key only** (`ANTHROPIC_API_KEY`). Anthropic does not
permit third-party products built on the Claude Agent SDK to offer claude.ai
login, so there is no subscription path here.

Two limits worth stating plainly. The runner bounds what the session can
**name**; the broker, in its own process, bounds what happens when the session
names it — you need both, and neither substitutes for the other. And that
`tools=[]` removes the built-in tools is a guarantee made by the SDK, not one
this repository verifies: the tests assert the option is set, and set to the
empty list rather than left to a default.

---

## 3. Develop on it

### Full setup

```bash
git clone https://github.com/impactRssi/agent-boundary
cd agent-boundary
uv sync --group dev --group gui --extra mcp --extra runner
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
checks the MCP adapter, the runner and the GUI tier, so all three need to be
present:

| Command | Unlocks |
|---|---|
| `uv sync --group dev` | format, lint, unit, adversarial, sast, audit |
| `+ --extra mcp` | `make types` (the MCP adapter is type-checked) |
| `+ --extra runner` | `make test-e2e` — the tier builds real agent-SDK session options, offline |
| `+ --group gui` | `make test-gui` — plus `uv run playwright install chromium` |
| `brew install gitleaks` | `make secrets` |

The `runner` extra pulls an agent SDK, and it stays an extra. `[project]
dependencies` is `[]` and a unit test keeps it that way: the authorisation path
— broker, guards, confinement, budget, ledger, ingest — imports nothing outside
the standard library, whatever the runner comes to need
([ADR-0009](adr/ADR-0009-model-in-the-loop-evidence-is-not-a-benchmark.md) §6).
No test tier calls a model or needs `ANTHROPIC_API_KEY`.

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
