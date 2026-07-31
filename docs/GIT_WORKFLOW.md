# Git Workflow

**Scope:** All work in this repository.

**Goal:** A history that reads like the project's evidence trail — every commit buildable, every PR reviewable, no surprise conflicts.

## 1. Branch model

| Branch | Purpose | Rules |
|---|---|---|
| `main` | Always-green integration branch | Every commit builds, passes `swift test`, and passes format lint. No direct feature commits. |
| `feat/<scope>-<short-name>` | One feature or plan step | Short-lived (days, not weeks). Branched from latest `main`. |
| `fix/<scope>-<short-name>` | One bug fix | Same rules as feature branches. |
| `docs/<short-name>` | Documentation-only change | May be merged with a fast review. |

Examples: `feat/bridge-fake-app-server`, `feat/bridge-approval-wiring`, `fix/protocol-envelope-decoding`, `docs/phase-1-status`.

There are no long-running development branches. Long-lived branches are the primary source of merge conflicts; every branch should merge or be deleted within a few days.

### Scopes

Use the source target (or area) the change belongs to:

- `protocol` — `Sources/CompanionProtocol`
- `bridge` — `Sources/MacBridgeCore`
- `appserver` — `Sources/CodexAppServer`
- `spike` — `Sources/CodexMicroSpike`
- `macapp` — the signed Mac app target (Phase 1 Step 5)
- `ios` — the iOS app target (Phase 3)
- `docs`, `ci`, `build` — non-source areas

## 2. When to commit

Commit when a **single logical unit** is complete, not at the end of the day:

- The code compiles and all existing tests pass. A commit that breaks the build is never acceptable, even on a feature branch — it destroys `git bisect`.
- One concern per commit. "Add approval expiry check" and "rename ledger enum" are two commits, not one.
- New behavior lands in the same commit as its tests, or the tests come first. Never commit untested state-changing logic with the intent to "test later."
- Documentation that describes a change (e.g. `PHASE_1_STATUS.md`) is updated in the same commit or the same PR as the change itself.

Never commit:

- Secrets, tokens, keys, or Keychain exports of any kind.
- `.build/`, `.swiftpm/`, `xcuserdata/`, or other generated/user-local files (enforced by `.gitignore`).
- Sanitized fixtures that are not actually sanitized — fixture files must contain no real prompt text, file paths, credentials, or thread content. Verify before staging.

## 3. Commit message format

Use [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <imperative summary, ≤72 chars>

<body: what changed and WHY, wrapped at 72 chars>
<reference the phase/step it belongs to when applicable>
```

**Types:** `feat`, `fix`, `docs`, `test`, `refactor`, `perf`, `build`, `ci`, `chore`.

Rules:

- Summary is imperative mood: "add approval digest check", not "added" or "adds".
- Summary explains *what*; body explains *why* and any non-obvious decision.
- Reference the plan in the body, e.g. `Phase 1, Step 2 (approval-response wiring).`
- A breaking protocol change (wire format, ledger schema, snapshot version) uses `!` and a `BREAKING CHANGE:` footer: `feat(protocol)!: ...`
- Commits authored with AI assistance keep the `Co-Authored-By:` trailer.

Good examples:

```
feat(bridge): add fake app-server scenario harness

Deterministic scenarios for every consumed notification and
approval type, plus malformed and unknown-message cases. Enables
approval-wiring and degraded-restart tests without live Codex
allowance.

Phase 1, Step 1.
```

```
fix(appserver): reject turn events with conflicting thread routes

A turn/started carrying a thread ID that contradicts the recorded
route previously logged and continued; it now fails closed per the
event-router contract.
```

Bad examples (do not write these): `wip`, `fixes`, `update code`, `changes as discussed`, `final version 2`.

## 4. When to open a PR

- **One PR per plan step or coherent feature.** The current Phase 1 close-out plan maps to one PR per step (fake app-server harness; approval wiring; degraded restart; redacted logger; Mac app shell + ledger path; exit-gate verification).
- Open the PR when the branch builds, all tests pass, and the change is self-reviewed. Open a **draft PR** earlier if you want a visible checkpoint while still working.
- Keep PRs reviewable: target under ~500 changed lines of non-generated code. If a step grows beyond that, split it into stacked PRs rather than one large one.
- Every PR description contains:
  1. **What** — one paragraph on the change.
  2. **Why** — the plan step or issue it addresses.
  3. **Verification** — exact evidence: test counts, build configurations run, and any live probe output (sanitized). Follow the project rule: source-only or simulator-only evidence is never called release proof.
  4. **Security notes** — anything touching approvals, the ledger, policy, crypto, logging, or fixtures states what fails closed and what was checked for content leaks. Write "None" explicitly when not applicable.

## 5. When to merge

Merge a PR only when **all** of these hold:

1. `swift test` passes (all targets).
2. `swift build -c release` passes.
3. Swift format lint passes.
4. Status docs affected by the change are updated in the PR.
5. The PR has been reviewed — by the other collaborator when there is one, or as a deliberate self-review pass (read the full diff top to bottom) when working solo.
6. The branch is up to date with `main` (rebase the branch, re-run tests, then merge).

**Merge method: squash merge.** One PR becomes one commit on `main`, titled with a conventional-commit summary. This keeps `main` linear, bisectable, and readable as a change log. Delete the branch immediately after merging.

Never merge: red tests "to fix on main later", commented-out test assertions, or force-pushes to `main`. `git push --force` is forbidden on `main` under all circumstances; on feature branches, prefer `--force-with-lease` after a rebase.

## 6. Conflict avoidance

Conflicts come from overlap and age. Prevent both:

- Start every branch from freshly pulled `main`: `git fetch origin && git switch -c feat/... origin/main`.
- Rebase active branches on `main` at least daily, and always before opening/merging a PR.
- **One area per branch.** Two open branches must not edit the same files. If two steps both need to touch a shared file (e.g. `PHASE_1_STATUS.md`), sequence the PRs instead of parallelizing them.
- Status docs are the known conflict hotspot — each PR updates only the lines about its own step.
- Finish branches. A branch older than a week is either merged, split, or deleted.

## 7. Tags and milestones

- Tag each phase acceptance on `main`: `phase-0-accepted`, `phase-1-accepted`, …
- Tags are annotated (`git tag -a`) and their message cites the evidence snapshot (test counts, build results) recorded in the status doc.
- Semantic versioning (`v0.x.y`) starts when the first app target ships to TestFlight; until then, phase tags are the milestones.

## 8. Quick reference

```bash
# start work
git fetch origin
git switch -c feat/bridge-fake-app-server origin/main

# during work — commit small, buildable units
swift test && git add -p && git commit

# before PR
git fetch origin && git rebase origin/main
swift test && swift build -c release

# after squash-merge on GitHub
git switch main && git pull origin main
git branch -d feat/bridge-fake-app-server
```
