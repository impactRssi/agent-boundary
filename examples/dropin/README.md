# Drop-in configuration

Point an MCP-capable agent runtime at `python -m agentboundary`. The task file
is the security configuration: tool scope, filesystem root, egress allowlist,
and caps. Treat it as a reviewed artifact, not as something improvised at the
command line.

## Task file

[`task.support-triage.json`](task.support-triage.json) scopes a read-only
triage task. Note what it does **not** grant:

- `fs.write` is absent from `tool_scope`, so it has no handle the model can name.
- `egress_allowlist` is empty, so all egress is denied. A task that needs the
  network says so explicitly.
- `tickets.comment` is in scope but classified irreversible, so it still needs
  an out-of-band approval before it can post.

Every omission fails closed. A missing cap is an error rather than a generous
default — an operator who forgot to set a limit has not decided there should be
none.

## Claude Desktop / Claude Code

`.mcp.json` in the project root, or `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "agent-boundary": {
      "command": "python",
      "args": [
        "-m", "agentboundary",
        "--task", "examples/dropin/task.support-triage.json",
        "--tickets", "examples/dropin/tickets.json",
        "--approvals", "/etc/agent-boundary/approvals.json",
        "--audit", "/var/log/agent-boundary/trace.jsonl"
      ]
    }
  }
}
```

Two placements matter:

- **`--approvals` lives outside `fs_root`.** An approval store the agent can
  write to is not out of band. Here `fs_root` is `./workspace` and the
  approvals file is in `/etc`, so no scoped filesystem tool can reach it.
- **`--audit` lives outside `fs_root`** for the same reason. A trace the agent
  can rewrite is not a trace.

## Check the configuration before serving

```bash
python -m agentboundary --task examples/dropin/task.support-triage.json \
    --tickets examples/dropin/tickets.json --dry-run
```

Prints the resolved scope, root, allowlist, and caps, then exits. Run it after
every edit to the task file: the scope you meant and the scope you wrote are
not always the same, and this is the cheapest place to find that out.

## Handlers

`python -m agentboundary` ships the reference handlers — real filesystem, real
HTTP, and a JSON-file ticketing backend so the example runs without an account.
A real deployment substitutes its own by importing
`agentboundary.mcp.server.BrokeredServer` directly; see
[`../support_triage.py`](../support_triage.py).

No handler re-checks scope, confinement, egress, budget, or approval. By the
time a handler runs the broker has decided, and a handler that defended itself
would be saying the guard was advisory.
