# Specification — Agent Boundary

Normative specification for the tool-call broker. Requirement keywords MUST,
MUST NOT, SHOULD, and MAY are used in the RFC 2119 sense.

Derived from `docs/THREAT_MODEL.md`. Every requirement below traces to one of
the four structural invariants (I1–I4) or to an accepted decision record.

§7 and §8 are the acceptance criteria and stated limitations of `v0.1.0` and
are kept as that release's record. The current limitations live in
`docs/THREAT_MODEL.md` §7 and in the README's Limitations section, which are
the two that stay up to date.

---

## 1. Purpose and scope

Agent Boundary sits between an LLM agent and the tools it can reach. It decides
which proposed tool calls become effects, deterministically and without
consulting a model.

**In scope:** per-task tool scoping, argument schema validation, filesystem and
egress confinement, budget accounting, irreversibility gating, ingest of tool
results, an append-only audit trace, an append-only refusal ledger, and
operator-granted permission leases that are bounded in time by construction.

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
| `Lease` | `kind`, `subject`, `granted_by`, `reason`, `granted_at`, `expires_at`, `sensitivity`, `task_id` | Immutable. `kind` ∈ `tool` \| `path` \| `host`; `sensitivity` ∈ `credential` \| `sensitive` \| `routine`. `expires_at` has no default and no value of it means "never" |
| `LedgerEntry` | `subject_kind`, `subject`, `resolved`, `reason`, `first_seen`, `last_seen`, `count`, `sample_task_ids` | Evidence about the past. Carries no approval field and no method that produces one |
| `RotationAdvice` | `lease_digest`, `kind`, `subject`, `granted_by`, `reason`, `granted_at`, `expires_at`, `task_id` | Emitted on expiry of a `credential` lease, unconditionally |

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

### 4.10 Permission leases — I1, I3, I4

A lease is the one mechanism that makes an invariant hold *less* than it did,
for one subject and for a bounded period. The requirements below exist to bound
that. Rationale and rejected options: `ADR-0008`.

- **FR-027** A lease MUST carry a kind, a subject, `granted_by`, a reason,
  `granted_at`, `expires_at`, and a sensitivity class. Every one of them MUST
  be required; an empty `granted_by` or reason MUST be refused at construction,
  because an unattributable or unexplained widening is not reviewable.
- **FR-028** A lease with no expiry MUST be unrepresentable. `expires_at` MUST
  have no default, non-finite values MUST be refused, and `expires_at` MUST be
  strictly after `granted_at`. An absent `expires_at` in a stored record MUST
  be an error and MUST NOT become a default, a sentinel, or a long window.
- **FR-029** The window MUST be capped per sensitivity class — 7 days for
  `credential`, 14 for `sensitive`, 30 for `routine` — and a lease exceeding
  its class cap MUST be refused at construction. Without a cap, "forever" is
  expressible as a large integer, which defeats FR-028.
- **FR-030** An unstated sensitivity class MUST default to `credential`, the
  class with the shortest cap and the mandatory rotation advisory. An
  unrecognised class MUST be refused and MUST NOT be silently downgraded. Same
  reasoning as FR-014: the unsafe default is the one that is not convenient.
- **FR-031** An expired lease MUST authorise nothing. The active window MUST be
  half-open — from `granted_at` inclusive to `expires_at` exclusive — and the
  clock MUST be injectable so the expiry path is testable without waiting.
- **FR-032** Path and host leases MUST be consulted **at call time** by the
  confinement guards, and MUST widen only the single check they attach to. A
  path lease MUST be admitted by the same resolution and containment test used
  for `fs_root` under FR-009, never by pattern matching. A host lease MUST
  widen only the allowlist membership test and MUST NOT relax the scheme
  allowlist, the hostless-URL refusal, the address-literal root-label refusal,
  or the loopback and link-local refusals.
- **FR-033** Tool leases MUST be resolved **at task construction time only**,
  producing a new immutable task. A running task's dispatch table MUST NOT
  change, because I1 is the property that an out-of-scope tool has no handle
  and a call-time dispatch filter is what `ADR-0002` rejects. The consequence
  MUST be stated rather than mitigated: a tool lease that expires mid-task
  keeps its handle until the task ends.
- **FR-034** A leased tool absent from the registry MUST fail task construction
  under FR-003. A lease MUST NOT create a capability the deployment never
  registered.
- **FR-035** A path lease whose subject resolves to the filesystem root MUST be
  refused. That is not a widening of I4 but its removal, on a timer.
- **FR-036** No component reachable from the agent loop MAY create a lease. The
  lease store MUST expose no grant operation, and leases MUST arrive already
  written from an operator channel.
- **FR-037** The lease store, the refusal ledger, and the rotation advisory
  sink MUST each be refused at construction if they lie inside the task's
  `fs_root`. A store that cannot be read or parsed MUST fail closed and MUST
  NOT resolve to "no leases", which an operator would misread as an expiry.
- **FR-038** Every refused call MUST be recordable in an append-only refusal
  ledger, aggregated by normalised subject and reason with first seen, last
  seen, count, and a bounded sample of task ids.
- **FR-039** No ledger type MAY carry an approval field or expose a method that
  produces permission, and no import edge MAY exist between the ledger and the
  lease module in either direction. Granting MUST name its subject explicitly
  and MUST NOT be derived from, or indexed into, the ledger — a ledger row is
  attacker-influenced data, and an index into it makes bulk approval one
  keystroke away (A3, A9).
- **FR-040** Every rendering of the ledger MUST carry, in its own output, the
  statement that a row cannot distinguish a legitimate workflow from a payload
  that steered the agent.
- **FR-041** An expired `credential`-class lease MUST produce a rotation
  advisory naming the subject, the window, the grantee, and the stated reason.
  Emission MUST be unconditional and MUST NOT depend on the audit trace looking
  clean: the trace records what was *authorised*, not what was *read*. The
  advisory MUST state that limit in its own text, and MUST be deduplicated by
  lease digest so that unconditional does not mean repeated.
- **FR-042** Leases MUST NOT introduce a refusal reason. A call a lease did not
  admit MUST refuse with `path_outside_root` or `egress_host_not_allowed` as it
  would have without one; whether a lease was consulted belongs in the check
  detail, so the machine-readable interface does not shift under an operator.

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
| 4.10 Permission leases | ✔ | ✔ | ✔ | — |

The GUI cell for 4.10 is empty because it is true, not because the row is
pending: at time of writing the audit-trace viewer has no lease surface, so
there is nothing for a browser test to assert. Unit coverage is
`tests/unit/test_leases.py`, `tests/unit/test_lease_application.py`,
`tests/unit/test_ledger.py`, and `tests/unit/test_rotation.py`; adversarial is
`tests/adversarial/test_leases_are_not_forgeable.py` and
`tests/adversarial/test_refusal_ledger_confers_nothing.py`; end-to-end is
`tests/e2e/test_lease_store.py`, `tests/e2e/test_lease_application.py`,
`tests/e2e/test_refusal_ledger.py`, and `tests/e2e/test_rotation_advice.py`.

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
