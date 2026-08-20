# Working methods

How work is decomposed, assigned, reviewed, and merged in this repository.
This document is normative. A change that does not follow it does not merge.

---

## 1. Priority order

Every trade-off is resolved in this order, and the order is not negotiable:

**security → correctness → minimal diff → tests → maintainability**

When two of these conflict, the one on the left wins and the reason is written
down — in the pull request if it is local to the change, in an ADR if it
constrains future work.

### Standing engineering rules

- Production threat model by default. Least privilege everywhere.
- Never hardcode secrets. Environment variables plus a committed `.env.example`
  in which every secret is referenced and none is valued.
- Smallest effective change. No refactor outside the task at hand.
- No heavy dependency without a written justification in an ADR.
- Targeted tests for every behaviour change; security-critical paths first.
- If something cannot be verified, say so explicitly and state what still needs
  manual checking. Silence is not evidence.
- No generated documentation unless the document is itself a listed deliverable.
- Artifacts are written in English. No academic framing, no student-project
  markers.

---

## 2. Graph engineering

Work is not a list. It is a directed acyclic graph of **work nodes**, and the
graph is the planning artifact.

### 2.1 What a node is

A node is a unit of work that is independently reviewable and independently
mergeable. It carries:

| Field | Meaning |
|---|---|
| `id` | Stable identifier, e.g. `N-07` |
| `title` | One line, imperative |
| `owner` | The role accountable for the node (§3) |
| `depends_on` | Node ids that must be merged first |
| `invariant` | Which structural invariant this node upholds, or `none` |
| `exit` | The observable condition that closes the node |
| `tests` | Which test tiers must pass (§5) |

Nodes live in `ROADMAP.md`. The graph is the source of truth for sequencing;
the phases in `ROADMAP.md` are only a readable projection of it.

### 2.2 Rules on the graph

1. **No cycles.** If two nodes need each other, they are one node, or the
   boundary between them is wrong. Redraw it before writing code.
2. **An edge is a real dependency, not a preference.** "Nicer to do after" is
   not an edge. An edge means the downstream node cannot be correct until the
   upstream one is merged.
3. **Nodes with no path between them may proceed in parallel** on separate
   branches. This is the whole point of maintaining the graph.
4. **A node that cannot state its `exit` condition is not ready to start.**
   It goes back for decomposition.
5. **Cutting scope means removing leaf nodes**, never weakening the exit
   condition of a node that is kept.

### 2.3 Frontier

At any moment the **frontier** is the set of nodes whose dependencies are all
merged into `main`. Only frontier nodes may be assigned. Starting a node off
the frontier produces a branch that will be rewritten, which is waste.

---

## 3. Roles and accountability

The work is split across specialised roles. Every role reports to a single
technical owner who assigns nodes, arbitrates trade-offs, and holds the merge
decision.

| Role | Owns | Does not own |
|---|---|---|
| **Technical lead** | The graph, node assignment, merge decisions, ADR acceptance, scope | Writing feature code unreviewed |
| **Broker engineer** | The deterministic authorisation path: allowlist, schema validation, budget accounting, irreversibility classification | Anything that reinterprets tool output |
| **Ingest engineer** | Normalisation, active-content stripping, data delimiting, provenance tagging of untrusted content | Authorisation decisions |
| **Security engineer** | Threat model, adversarial corpus, SAST/dependency policy, secrets policy, disclosure process. Holds a **blocking veto** on any change that weakens an invariant | Feature scope, schedule |
| **Test engineer** | Test architecture across the three tiers, CI wiring, coverage of security-critical paths, flake elimination | Deciding what is or is not a vulnerability |
| **Benchmark engineer** | Reproducible, offline-by-default measurement harness and published caveats | Publishing a number without its caveat |
| **Documentation owner** | README, threat model, ADRs, limitations | Claiming a property that has no test |

Two rules bind the roles together:

- **The technical lead verifies; the lead does not rubber-stamp.** Every node
  is checked against its own stated `exit` condition before merge, not against
  the author's summary of it.
- **The security engineer's veto is structural.** It can be overridden only by
  an accepted ADR that records what residual risk was consciously accepted, and
  who accepted it.

---

## 4. Branching and merging

### 4.1 Naming

Every branch that carries work is named:

```
feature/<feature-name>
```

Lowercase, hyphen-separated, describing the feature and not the person or the
ticket. `feature/tool-allowlist`, not `feature/tom-wip` or `feature/AB-42`.

`main` is the only long-lived branch. There is no `develop`.

### 4.2 One node, one branch

A branch implements one node. If a branch grows a second concern, that concern
is a new node on a new branch — even when it is small, and especially when it
is tempting.

### 4.3 Merge policy

A branch merges into `main` **only when the feature is complete**. Complete
means the node's `exit` condition is observably met and every required test
tier passes. There are no partial merges, no "will finish next branch", and no
feature flags used to hide unfinished work behind a merge.

Merges are `--no-ff`. The merge commit is the record that a node closed, and
the history should show it.

`main` is expected to be releasable at every commit.

### 4.4 Commit messages

Conventional Commits, imperative mood, English:

```
<type>(<scope>): <subject>

<body: why, not what. The diff already says what.>
```

Types in use: `feat`, `fix`, `docs`, `test`, `refactor`, `perf`, `build`,
`ci`, `chore`. Security-relevant changes state the invariant they touch in the
body.

---

## 5. Testing

Three tiers. All three are blocking in CI. A change that adds behaviour without
adding tests at the appropriate tier does not merge.

### 5.1 Unit — the test suite

- `pytest` under `tests/unit/`, one module per source module.
- Deterministic, offline, no network, no clock dependence.
- Every branch of the authorisation path is exercised, including the refusal
  branches. Refusals are the product; they are tested first.
- Coverage is measured and reported. Coverage of the broker package is a
  blocking threshold, not an advisory number.

### 5.2 Adversarial — the corpus

- `tests/adversarial/`, selected by the `security` marker.
- Each payload in the indirect-injection corpus is a test asserting that the
  broker **refused** the resulting call.
- This suite runs as a **separate blocking CI step** and fails the build if it
  collects zero tests or skips one. A corpus that can silently collect nothing
  is not a control.
- New payload classes are added by the security engineer, not by whoever
  happens to be fixing a bug.

### 5.3 End-to-end and GUI

- `tests/e2e/` drives a real agent runtime against a real broker process over
  the wire, with real tool handlers pointed at throwaway fixtures. No mocks at
  the boundary under test.
- `tests/gui/` uses Playwright against the audit-trace viewer, in a real
  browser, asserting on what an operator can actually see: that a refused call
  is visible as refused, that attribution is present, that nothing in a trace
  can be edited from the interface.
- Where a deliverable has no interface, the GUI tier is recorded as
  "not applicable" for that node in `ROADMAP.md` — explicitly, with a reason.
  It is never silently absent.

### 5.4 Definition of done

A node is done when, and only when:

- [ ] The stated `exit` condition is observably met.
- [ ] Unit tests cover the new behaviour, including its failure modes.
- [ ] Adversarial coverage exists if the node touches an invariant.
- [ ] E2E passes; GUI passes or is recorded as not applicable with a reason.
- [ ] Lint, type check, SAST, dependency audit, and secret scan are clean.
- [ ] Documentation reflects reality, and any new limitation is written into
      the Limitations section rather than left implied.
- [ ] The technical lead has verified the above against the node, not against
      the summary.

---

## 6. Evidence and honesty

- Every claim in the README traces to a file, and where automated coverage
  exists, to a test. Where it does not exist, the README says so.
- Numbers are published with their caveats attached, in the same sentence. The
  caveat is what makes the number credible.
- A Limitations section is mandatory and is maintained as the project changes.
  Overselling reads as junior. Precise limits read as senior.
- When infrastructure is missing, the system fails closed and reports that
  state out loud. It never proceeds quietly.
