# ADR-0008 — Permission leases are bounded by construction, and a refusal grants nothing

- **Status:** Accepted
- **Date:** 2026-08-23
- **Bounds a deliberate widening of:** I1, I3, I4
- **Constrained by:** `ADR-0002`

## Context

Two forces meet here, and both are real.

**The first: an operator sometimes has to widen a task's scope.** An automation
needs three days of access to a credential directory; a migration needs one
internal host that is not in the allowlist; a one-off job needs a tool the task
was not scoped for. The only mechanism this repository offered before this
decision was task construction — edit `fs_root`, add the host, add the tool.
That mechanism has no expiry. Nothing in it forces the decision to be made again, so the widening
that was justified on a Tuesday is still in force a year later, and nobody
remembers why. **The absence of a temporary mechanism is what produces
permanent grants**, which is the failure mode this ADR exists to avoid.

**The second: an operator wants to know what the broker has been refusing.**
That is the refusal ledger (`src/agentboundary/ledger.py`), and it is where the
whole feature can go wrong in one step. A list of refusals reads like a list of
requests. The chain from there is short: attacker-writable content steers the
agent toward a secret, the broker refuses, the refusal is written down, and a
human later approves "the things the agent needed". That is attack A3 (confused
deputy) and A9 (approval fatigue) from `docs/THREAT_MODEL.md` §6 wearing a
helpful interface, and the interface is what makes it work.

Constraining all of it is `ADR-0002`: I1 is the property that an out-of-scope
tool has **no handle**. It is absent from the schema the model is shown and
absent from the dispatch table. Any mechanism that puts a tool into a live
dispatch table converts I1 from a structural property into a call-time filter —
the exact shape `ADR-0002` rejected.

## Decision

A widening is a **lease**: `src/agentboundary/leases.py`. Five parts, each of
which is a constraint rather than an option.

### 1. Unbounded is unrepresentable, and the class caps are what make that true

`Lease` is a frozen dataclass whose `expires_at` has no default, so it cannot
be omitted — construction raises `LeaseError`. Infinity and NaN are rejected,
so the largest float cannot stand in for "never". `expires_at` must be strictly
after `granted_at`, so a lease that authorises nothing is a configuration error
rather than a quiet no-op. `LeaseStore` deliberately offers no `grant()`, for
the same reason `ApprovalStore` does not: anything holding a reference — the
agent loop included — could otherwise mint one.

None of that is sufficient on its own. Without a maximum window, "forever" is
just a large integer and nothing objects. So the window is capped **per
sensitivity class**, in `MAX_DURATION_S`:

| Class | Maximum window |
|---|---|
| `credential` | 7 days |
| `sensitive` | 14 days |
| `routine` | 30 days |

The cap is the tooth. Everything above it is bookkeeping.

Only the first number has a stated derivation, and it is a weak one: a
`credential` lease's expiry obliges a rotation, so a window longer than about a
week means the advice arrives too late to be actionable. Fourteen and thirty
are ordering choices — wider classes get wider windows — and neither is derived
from a measurement of how long a credential or an internal host stays valuable.
What is load-bearing is that *a* finite cap exists for every class and that the
tightest one applies to the class you get by saying nothing. A deployment with
different exposure should pick different numbers; it cannot pick none.

The class you get by saying nothing is `credential` — the shortest cap and the
mandatory rotation advisory. That is `FR-014`'s reasoning applied again: the
unsafe default is the one we refuse to make convenient. Declaring a subject
*less* sensitive is an explicit act with the grantee's name on it.

A lease whose subject resolves to the filesystem root is refused outright. That
is not a widening of I4, it is the removal of it, expressed in a form that
expires and is therefore easy to grant and forget.

### 2. Path and host leases resolve at call time; tool leases at construction

This distinction is load-bearing, and it is not symmetry we failed to achieve.

**Path and host leases are consulted at call time**, by
`PathConfinementGuard` and `EgressGuard` in `src/agentboundary/confinement.py`.
A lease widens an argument check, and an argument check is what those guards
perform. Three properties bound what one can do there:

- The path guard consults the store **only on the refusal branch**. A path
  already inside the root never reaches it, so an unreadable store cannot break
  ordinary work and a lease can never turn an authorisation into something
  else.
- Admission is decided by the same `contains()` against the same resolved form
  the task root gets. There is one path comparison in this package. A lease
  over `/x/secrets` therefore does not admit `/x/secrets-backup`, does not
  admit `/x`, and does not admit a traversal out of it.
- The host lease adds entries to the membership test and adds nothing else. It
  does not widen the scheme allowlist, does not admit a URL with no host, does
  not excuse an address literal carrying a root label, and does not disable the
  loopback and link-local refusal, which still runs afterwards.

**Tool leases cannot work that way.** They are resolved once, by
`leased_task()`, before the broker exists — producing a new frozen `Task` whose
`tool_scope` is wider. The task the broker holds is fixed for its whole life,
as it always was. A tool that appeared in the dispatch table partway through a
session would be the call-time filter `ADR-0002` rejects, and I1 would stop
being a structural property.

**The consequence, stated rather than hidden: a tool lease that expires
mid-task keeps its handle until the task ends.** The expiry bounds when a *new*
task may be constructed with that tool, not when a running one loses it. A task
constructed one second before expiry holds that tool for its whole life,
bounded only by the task's caps. Tool leases should therefore be short. An
operator who needs the capability gone now ends the task; there is no mechanism
here that removes it from a live one, and adding one would be the thing we just
refused.

A leased tool the registry does not know still fails task construction, loudly,
in `ToolRegistry.scope_for`. A lease cannot conjure a capability the deployment
never registered.

### 3. The refusal ledger grants nothing, and granting requires the subject to be typed

`LedgerEntry` carries no approval field, no expiry, no grantee, and no
identifier a grant could be keyed to. `RefusalLedger` has `record` and
`entries` and no counterpart — no `approve`, no `grant`, no `promote`. Neither
module imports the other. Both directions are asserted by introspection —
`tests/unit/test_ledger.py::TestTheLedgerConfersNothing` reads the ledger
module's own source for an edge to `agentboundary.leases`, and
`tests/unit/test_leases.py` does the reverse — so adding one breaks the build
rather than passing review.

The reason is not tidiness. **A ledger row is attacker-influenced data**: what
the agent reached for is steerable by whoever can write into its context, and a
legitimate workflow and an injected payload produce the identical row — a
subject, a reason, a count, some task ids. A high count means the agent tried
often, which is exactly what a retry loop induced by injected content looks
like.

So granting requires the operator to **type the subject**, every time. It is
never selected from an index into the ledger. An index makes bulk approval one
keystroke away, and approval fatigue is the failure mode this must not
manufacture. `ledger.render()` emits the caveat itself, above the rows, rather
than leaving it to each caller — a caller who forgets it publishes a list of
refusals that reads like a list of requests.

### 4. What a lease costs

**During its window, the invariant it widens does not hold for its subject.**

A path lease is a second root the task may reach; a host lease is one more
entry in the egress allowlist; a tool lease is one more handle in the dispatch
table. Nothing about the model changed and nothing about the guards changed —
the operator moved the boundary, on purpose, for a stated period, and the trace
says who did it and why. For the duration, a leased path is an unbounded path.

The levers that remain are the class caps, pinning the lease to a `task_id`,
and revoking early. There is no fourth one.

### 5. Rotation advice on expiry is unconditional

When a `credential`-class lease expires, `src/agentboundary/rotation.py` emits
an advisory naming the subject, the window, the grantee and the stated reason.
There is no "unless the trace looked clean" branch, and adding one would be a
defect.

The reason is evidentiary. **The audit trace records what was *authorised*, not
what was *read*.** Inside the lease window the guards were doing exactly what
the operator told them to, so a clean trace is what the legitimate case and the
exfiltrated case both look like. "Nothing looked wrong" is therefore not
evidence, and advice conditioned on it arrives only when it is already too late
to be news. The advisory carries that sentence in its own text, because a
caveat that lives in a document the reader might find later is a caveat that
does not travel with the claim.

Advisories are deduplicated by the lease's digest, against what the sink
already holds rather than against in-process state, so a sweep run by a
different process does not re-announce a rotation. Unconditional is not the
same as repeated.

## Consequences

**Accepted, including the parts that are bad.**

- A leased path is an unbounded path for the duration. This is the cost named
  in Decision §4, and it is the point of the feature rather than a side effect.
- A tool lease that expires mid-task keeps its handle until the task ends.
- A lease with no `task_id` applies to **every** task in the deployment. That
  is the default, because the motivating case is an automation whose task id
  changes on every run. It is also the widest thing a lease can express, and
  pinning is a narrowing lever that is not taken by default.
- The three caps are a policy choice, not a derived bound, as set out above.
  A deployment that adopts them without asking whether they fit its exposure
  has adopted our guess.
- Typing a subject is slower than clicking one, and that ergonomic cost is
  accepted deliberately.
- The lease store, the refusal ledger and the advisory sink are files. Each is
  checked at construction against the task's own `fs_root` and refused if it
  lies inside it (`assert_out_of_reach`), which is what stops a steered agent
  from granting itself a lease through its own filesystem tool. None is checked
  against another task's root or against any other process on the host: like
  the audit trace, integrity rests on the host, and host compromise is out of
  scope.
- An unreadable or malformed store fails closed. The guard refuses with the
  reason the argument earned — `path_outside_root` or
  `egress_host_not_allowed` — and says in the detail that the store could not
  be read. No new refusal reason was added, so the machine-readable interface
  is unchanged.
- **Not measured:** the published per-call overhead in `benchmarks/results.json`
  was measured with no lease store attached — `benchmarks/harness.py` builds
  `PathConfinementGuard()` and `EgressGuard()` with the default `leases=None` —
  so it says nothing about the cost of a `FileLeaseStore` re-read on the
  refusal branch. That number is not published because nobody has measured it.
- **No operator interface is described here.** Node N-45 is in flight and its
  command surface is not settled. This record covers the decisions, which are.

**Rejected: a persistent allowlist entry.** Add the path to `fs_root`, the host
to `egress_allowlist`, the tool to `tool_scope`, and move on. It is simpler,
it needs no new module, no store, no clock, and no expiry semantics — and it is
how this goes wrong everywhere else. Nothing forces the decision to be made
again. There is no moment at which someone has to justify the access a second
time, no artefact that names who widened the boundary and why, and no event
that triggers rotation of whatever was reachable. A permanent grant is
indistinguishable at review time from one nobody has thought about in two
years. The whole value of a lease is that it ends by default.

**Rejected: removing a tool handle at expiry.** It is what an operator expects
from a word like "lease", and it would make the three kinds symmetric. It also
requires the dispatch table to be consulted against a clock at call time, which
is `ADR-0002`'s global registry with call-time filtering, reintroduced under a
friendlier name. We keep the asymmetry and state the consequence instead.

**Rejected: approving directly from the refusal ledger.** The obvious
ergonomic win — the operator already knows what was refused, so let them grant
it from there. It makes every refusal an attacker induced into a pre-filled
grant candidate, and bulk approval into one keystroke. The ledger is evidence
about the past; it is never a request about the future.
