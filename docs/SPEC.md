# Specification — Agent Boundary v0.1.0

Normative specification for the tool-call broker. Requirement keywords MUST,
MUST NOT, SHOULD, and MAY are used in the RFC 2119 sense.

Derived from `docs/THREAT_MODEL.md`. Every requirement below traces to one of
the four structural invariants (I1–I4) or to an accepted decision record.

---

## 1. Purpose and scope

Agent Boundary sits between an LLM agent and the tools it can reach. It decides
which proposed tool calls become effects, deterministically and without
consulting a model.

**In scope:** per-task tool scoping, argument schema validation, filesystem and
egress confinement, budget accounting, irreversibility gating, ingest of tool
results, and an append-only audit trace.

**Out of scope:** defending against a malicious operator, constraining what a
permitted tool does internally, host compromise, and any claim about model
alignment. See `docs/THREAT_MODEL.md` §2 and §7.

---

## 2. Architecture

```
untrusted content (docs, tickets, web, tool responses)
        │
        ▼
   [ ingest ]   normalise · strip active content · delimit · tag provenance
        │
        ▼
   [ agent  ]   untrusted component — assume fully steered
        │
        ▼  ProposedCall
   [ broker ]   deterministic · model-free · the only authoriser
        │
        ▼  authorised call only
   [ effect ]   side-effecting call, logged with full attribution
        │
        ▼
   [ audit  ]   append-only trace a human can reconstruct the decision from
```

The broker is the load-bearing control. It reads no natural language, consults
no model, and takes no input from the agent's context.

---

## 3. Domain model

| Entity | Fields | Notes |
|---|---|---|
| `Task` | `id`, `tool_scope`, `fs_root`, `egress_allowlist`, `caps`, `created_at` | Immutable once constructed |
| `Tool` | `name`, `arg_schema`, `irreversibility`, `cost_weight`, `handler` | `irreversibility` ∈ `read` \| `reversible` \| `irreversible` |
| `ProposedCall` | `tool_name`, `arguments` | Untrusted. Originates from the agent |
| `Decision` | `outcome`, `reason`, `checks[]` | `outcome` ∈ `authorise` \| `refuse` |
| `AuditRecord` | `task_id`, `tool_name`, `validated_args`, `decision`, `result_status`, `timestamps` | Append-only |
| `ApprovalRecord` | `task_id`, `tool_name`, `arg_digest`, `granted_by`, `expires_at` | Out-of-band. Never constructible from context |
| `Caps` | `max_calls`, `max_cost`, `max_wall_clock_s` | Per task |

### Refusal reasons

Machine-readable and stable; they are part of the interface.

`tool_not_in_scope` · `schema_invalid` · `path_outside_root` ·
`egress_host_not_allowed` · `budget_exhausted` · `approval_required` ·
`approval_expired` · `approval_mismatch` · `tool_unknown` ·
`task_construction_failed`

---

## 4. Functional requirements

### 4.1 Task construction and tool scoping — I1

- **FR-001** The broker MUST resolve tool availability per task at construction
  time. Only in-scope tools appear in the schema presented to the model and in
  the dispatch table.
- **FR-002** A proposed call naming a tool outside the task scope MUST be
  refused with `tool_not_in_scope`, without invoking any handler and without
  the handler being reachable.
- **FR-003** Task construction MUST fail closed with
  `task_construction_failed` when the declared scope names a tool absent from
  the registry. It MUST NOT silently narrow the scope.
- **FR-004** A zero-tool scope MUST be legal. Every proposed call under it is
  refused.
- **FR-005** Tool name resolution MUST be exact match on normalised names.
  Fuzzy, prefix, and confusable-tolerant matching MUST NOT be implemented.

### 4.2 Argument validation — I3

- **FR-006** Every proposed call's arguments MUST be validated against the
  tool's declared schema before authorisation.
- **FR-007** Validation MUST precede budget accounting, so a malformed call
  cannot consume budget.
- **FR-008** Attribution, confinement checks, and the audit record MUST use the
  **post-validation** arguments, never the raw proposal.

### 4.3 Confinement — I4

- **FR-009** Filesystem path arguments MUST be confined to the task's
  `fs_root`. Symlinks and relative segments MUST be resolved *before* the
  confinement check. Pattern-matching the requested string MUST NOT be used as
  the confinement mechanism.
- **FR-010** Network egress MUST be confined to `egress_allowlist`, checked
  against the post-validation destination host.
- **FR-011** A request outside either confinement MUST be refused before any
  file handle is opened or any socket is created.

### 4.4 Budget and bounding — I3

- **FR-012** The broker MUST enforce per-task hard caps on call count,
  cumulative cost, and wall-clock time.
- **FR-013** On reaching any cap the broker MUST refuse with
  `budget_exhausted`, terminate the task in an explicitly failed state, and
  report that state. It MUST NOT continue in a degraded mode and MUST NOT stop
  silently.

### 4.5 Irreversibility and approval — I3

- **FR-014** Every tool MUST carry an irreversibility class. A tool registered
  without an explicit class MUST default to `irreversible`.
- **FR-015** A call to an `irreversible` tool MUST require a verified
  `ApprovalRecord` matching task id, tool name, and argument digest, and not
  past its expiry.
- **FR-016** The broker MUST NOT accept any approval signal originating from
  the agent's context. A claim in context that approval was granted MUST have
  no effect on the decision.
- **FR-017** An absent, expired, or mismatched approval MUST refuse with
  `approval_required`, `approval_expired`, or `approval_mismatch` respectively.

### 4.6 Ingest — I2

- **FR-018** Every tool result MUST pass through ingest before re-entering the
  model context: encoding and unicode normalisation, active-content stripping,
  data delimiting, provenance tagging.
- **FR-019** No code path MAY return a raw tool result to the agent loop. Only
  the ingested envelope is returned.
- **FR-020** A tool result that is itself well-formed JSON describing a tool
  call MUST be ingested as data and MUST NOT be dispatched.

### 4.7 Audit — I3

- **FR-021** The broker MUST write an append-only audit record for **every**
  proposed call, refused ones included, containing task id, tool name,
  post-validation arguments, decision, reason, ordered checks, and outcome.
- **FR-022** The audit store MUST expose no mutation or deletion path.

### 4.8 Authorisation isolation — ADR-0001

- **FR-023** The broker's only inputs MUST be the task construction and the
  proposed call. It MUST NOT read the model context.
- **FR-024** No probabilistic or model-based component MAY sit on the
  authorisation path.

### 4.9 Packaging

- **FR-025** The project MUST ship as an installable package plus a drop-in
  configuration for at least one common agent runtime.
- **FR-026** A worked example MUST wire an agent to a filesystem tool, an HTTP
  tool, and a ticketing tool.

---

## 5. Non-functional requirements

- **NFR-001** Broker overhead per call MUST be measured and published in
  milliseconds, with the conditions of measurement stated in the same sentence.
- **NFR-002** The broker's decision path MUST be deterministic: identical task
  and proposed call yield an identical decision and reason.
- **NFR-003** The benchmark harness MUST run offline by default and MUST be
  reproducible.
- **NFR-004** The project's own SAST MUST return zero high-severity findings
  against itself.
- **NFR-005** No secret is hardcoded. Every secret is referenced in
  `.env.example` and valued nowhere.

---

## 6. Verification

Every requirement maps to a test tier. `security` marks the blocking
adversarial subset.

| Requirement group | Unit | Adversarial | E2E | GUI |
|---|---|---|---|---|
| 4.1 Tool scoping | ✔ | ✔ | ✔ | — |
| 4.2 Argument validation | ✔ | ✔ | ✔ | — |
| 4.3 Confinement | ✔ | ✔ | ✔ | — |
| 4.4 Budget | ✔ | ✔ | ✔ | ✔ |
| 4.5 Approval | ✔ | ✔ | ✔ | ✔ |
| 4.6 Ingest | ✔ | ✔ | ✔ | — |
| 4.7 Audit | ✔ | — | ✔ | ✔ |
| 4.8 Isolation | ✔ | ✔ | — | — |
| 4.9 Packaging | — | — | ✔ | — |

**TR-001** The adversarial, end-to-end, and GUI suites MUST each fail the build
if they run zero tests or skip one. The count MUST be taken after selection,
not after discovery: a selection expression that deselects every payload leaves
a suite that discovered a corpus and asserted nothing, and a guard counting
discovery reports that as success.
**TR-002** Every row of the threat model's attack table (A1–A9) MUST have at
least one executable payload asserting refusal.
**TR-003** The injection corpus MUST contain at least 30 payloads across at
least 7 carrier types.

**TR-004** The reference MCP transport MUST be exercised by a test that runs it
as a separate process and drives it with a real client. A transport asserted
only through the in-process type it wraps is a transport nobody has run.

---

## 7. Acceptance criteria for v0.1.0

- **AC-001** An attacker who can write a ticket cannot cause the agent to read
  a file outside `fs_root`, call a tool outside `tool_scope`, exfiltrate to an
  unlisted host, or exceed `caps` — proven by the corpus running as a blocking
  CI step.
- **AC-002** Injection corpus results published as attempted/blocked, broken
  down by carrier type.
- **AC-003** False-refusal rate on the benign-task corpus published with its
  caveats.
- **AC-004** Per-call overhead published in milliseconds.
- **AC-005** Cap behaviour documented and demonstrated to fail closed.
- **AC-006** An operator can reconstruct any effect's decision from the audit
  trace alone.
- **AC-007** Limitations section present, specific, and current.

---

## 8. Stated limitations for v0.1.0

Carried forward from `docs/THREAT_MODEL.md` §7 and repeated here because a
specification that lists only what works is incomplete:

1. The allowlist bounds the blast radius; it does not make a dangerous tool
   safe.
2. Composition of two in-scope tools into an out-of-scope effect is bounded by
   attribution and approval, not prevented.
3. Data labelling reduces the rate at which payloads steer the model; it does
   not bound it. The design does not depend on it.
4. An allowlisted egress host that accepts attacker-readable content is an
   exfiltration channel.
5. No defence against a malicious operator, by design.
6. The benign-task corpus is synthetic and written by the same author as the
   controls. The measured 0/25 false-refusal rate means "no benign task the
   author thought of was refused", not "the control has no cost".
7. Concurrent tasks sharing a budget pool are not supported in v0.1.0.
8. No third-party review at time of writing.
