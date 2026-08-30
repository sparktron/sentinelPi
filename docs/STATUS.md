# Current Status

**Updated:** 2026-08-30 · **Branch:** `codex/phase-0-and-1` · **Commit:** `1d21347`

## Objective

A defensive network anomaly monitor that runs unattended on a Raspberry Pi: it baselines
normal traffic, reports deviations in plain language, and — only when explicitly armed —
can respond. Python package under `src/sentinelpi/`, deployed by systemd or Docker on the
Pi itself.

## Current state

- Version metadata is `1.0.0` (`pyproject.toml`); `v1.0.0` is the only tag.
- The checkout is on `codex/phase-0-and-1`, which is **20 substantive commits ahead of
  `master` and not merged into it**. `git rev-list --left-right --count master...HEAD`
  reports `1 21`; the merge base is `57e104c` ("Consolidate changelog under 1.0.0").
  Everything from `ea61cbf` ("Wire Phase 0 detection paths") through `b9372be` ("Make
  logging setup idempotent") — the whole 2026-07-12/13 review-correction programme — exists
  only on this branch. The extra commit on each side is the same AGENTS.md change applied
  twice: `f3fe6f3` on `master`, `1d21347` here, same subject, different SHAs.
- Local `codex/phase-0-and-1` matches `origin/codex/phase-0-and-1`, so the work is pushed,
  just not merged.
- `CHANGELOG.md` carries all of this under `[Unreleased]`; the last released section is
  `[1.0.0] - 2026-06-29`.
- `.github/workflows/ci.yml` triggers only on `push`/`pull_request` to `master`. No push to
  this branch runs CI, and no PR state was checked from here.
- `docs/` holds the operator set (`configuration_guide.md`, `systemd_setup.md`,
  `troubleshooting.md`, `threat_model.md`, `security_considerations.md`) plus
  `CODE_REVIEW.md` and the two roadmaps.

## Active work

Phase 4, "Operational Visibility And Control", in `docs/DEVELOPMENT_ROADMAP.md`. Its first
checkpoint — the runtime component/capability registry that drives event and poll routing
and reports lifecycle state through preflight and `/api/status` — shipped in `ca0e486`. Six
items under that phase remain unchecked (per-detector baseline readiness and reset/freeze
controls, per-sensor/exporter credentials with identity binding, sanitized PCAP/flow
fixtures, unified trust/whitelist/mute policy, notification delivery tracking, delivered
scheduled reports).

Uncommitted working-tree state: `git status --porcelain` reports one entry, `?? .claude/`
(untracked, containing `.claude/settings.local.json`). No tracked file is modified.

## Next

1. Decide what happens to `codex/phase-0-and-1` — merge it to `master` or open a PR, so the
   20 commits of review-correction work stop living only on a side branch and start passing
   through CI.
2. Continue the remaining Phase 4 items in `docs/DEVELOPMENT_ROADMAP.md`.
3. Restore a working local test environment (see Known problems) so the suite can be run
   outside GitHub Actions.

## Blockers

- No local validation is possible on this host. The repo's `venv/` is unusable and neither
  `pytest`, `ruff` nor `mypy` is installed for the system Python; installing dependencies
  was out of scope for this update.

## Known problems

- **CI does not cover the branch the work is on.** `ci.yml` fires only for `master`, and
  every current commit is on `codex/phase-0-and-1`. Confirmed by reading the workflow's
  `on:` block against `git branch -a -v`.
- **The in-repo `venv/` is stale and broken.** `venv/pyvenv.cfg` records
  `command = /usr/bin/python3.11 -m venv /home/mythos/repos/sentinelPi-/venv` — a different
  interpreter and a different machine's path. `venv/bin/python3.11` symlinks to
  `/usr/bin/python3.11`, which is absent here (only `/usr/bin/python3.10` exists), so
  `venv/bin/pytest` fails with `bad interpreter: No such file or directory`. Its
  `site-packages` is a Python 3.11 tree and cannot be borrowed by 3.10 either — importing
  `pytest` from it fails on the missing `exceptiongroup` back-port. `venv/` is gitignored,
  so this is local-only breakage, not a repository defect.

## Validation state

Everything below was run on 2026-08-30 on the machine holding this checkout: Linux
`6.8.0-136-generic`, **x86_64**, system Python **3.10.12**.

- `python3 -m compileall -q src tests` → exit 0, no diagnostics. Both trees byte-compile
  cleanly under Python 3.10, the project's declared minimum. This is the only repository
  check that was executed.
- Static inventory: 55 files in `tests/`, 466 `def test_` definitions. This is a text count
  of test functions, not a collected count — parametrisation makes the two differ — so it is
  a rough cross-check on the documented suite size, not a substitute for running it.

Not run: `pytest`, `ruff check src tests`, `mypy`, the packaging smoke test. See Unverified.

## Unverified

- **The 476-passing-test claim.** `docs/DEVELOPMENT_ROADMAP.md`, `docs/CODE_REVIEW.md`,
  `CHANGELOG.md` and `README.md` all state the suite contains 476 tests and passes together
  with Ruff, mypy and compileall as of 2026-07-13. That was **not** reproduced here: the
  test runner could not be started (see Known problems). Treat the number as documented, not
  as demonstrated — it is neither confirmed passing nor observed failing as of 2026-08-30.
- **Anything about behaviour on real Pi hardware.** This host is x86_64 Linux, not a
  Raspberry Pi, and nothing in the repository or on this machine records an on-device run.
  Even a fully green host suite would not cover the paths that only exist on the device:
  live packet capture through Scapy on a real NIC, promiscuous/mirror-port capture,
  `iptables`/`nftables` and `arp`/`ip neigh` responders, the DNS-sinkhole backends, the
  hardened systemd unit and its capability set, SD-card write behaviour, and sustained
  memory/CPU behaviour on a constrained board. **Host-green is not device-validated**, and
  no device validation is on record.
- **GitHub state.** CI run history, whether a PR exists for `codex/phase-0-and-1`, and
  release/artifact status were not queried.
- **Whether the branch is meant to merge to `master`,** or is deliberately parked.

## Recent decisions

- `docs/CODE_REVIEW.md` — repository-wide review dated 2026-07-12, corrective findings
  recorded closed 2026-07-13. It is the origin of the Phase 0–3 backlog and names the two
  critical wiring defects (`PortScanDetector` never registered; `DeviceTracker` alerts never
  dispatched) that isolated unit tests had missed.
- The corrective sequence itself, as commits: `ea61cbf` → `e93bfde` → `a3f63c5` → `e7a5b49`
  → `ac36dae` → `01565c0` → `9f7ef0c` → `a826f49` → `41674db` → `e0d0728` → `e5baa9b` →
  `35d3e6e` → `9e53628` → `0b61849` → `0295621` → `9d3511c` → `15f1798` → `ca0e486` →
  `b9372be` → `2065daa`.
- `e0d0728` "Default deployments to least privilege" — default systemd and Compose
  deployments grant `NET_RAW` only; `NET_ADMIN` moved behind the explicit
  `docker-compose.response.yml` override.
- `1d21347` (2026-07-26) "docs: add AGENTS.md as agent-instruction source of truth" —
  `AGENTS.md` is the single source; `CLAUDE.md` is one line, `@AGENTS.md`.

## Deep context

| Topic | Document |
|---|---|
| Current state | `docs/STATUS.md` (this file) |
| Roadmap — active | `docs/DEVELOPMENT_ROADMAP.md` |
| Roadmap — feature history | `docs/FEATURE_ROADMAP.md` |
| Latest repository review | `docs/CODE_REVIEW.md` |
| Design constraints | `docs/threat_model.md`, `docs/security_considerations.md` |
| Configuration | `docs/configuration_guide.md` |
| Deployment | `docs/systemd_setup.md` |
| Operator troubleshooting | `docs/troubleshooting.md` |

### On the two roadmaps

They are a **sequence with a live document and a historical one**, not a conflict, and each
file says so itself.

- `FEATURE_ROADMAP.md` is the older, product-shaped roadmap: "evolve SentinelPi from a
  strong single-host anomaly monitor into **the protector of the whole network**", organised
  as Phase 0–6. Its third paragraph states its own status explicitly: "The original Phase
  0–6 roadmap is retained below as implementation history. As of 2026-07-13 … Current
  follow-on work is tracked in the [Development Roadmap](DEVELOPMENT_ROADMAP.md); the active
  phase is **Phase 4: Operational Visibility And Control**." Almost every item in it carries
  a ✅ and a ship date; its closing section is headed "Completed follow-up session
  (historical)" and repeats "New work should use the active backlog in
  `DEVELOPMENT_ROADMAP.md`."
- `DEVELOPMENT_ROADMAP.md` is the live one. Its header reads "_Created: 2026-06-10 ·
  Updated: 2026-07-13. Scope: full repository review_", and it is organised around the
  2026-07-12 review rather than around product features. Its Phase 0–3 are marked completed
  2026-07-12 with per-phase suite counts (408 → 418 → 443 → 469), and Phase 4 is the only
  phase carrying unchecked boxes — "Status: in progress 2026-07-13."
- The handoff is one-directional and consistent: the feature roadmap points forward to the
  development roadmap, the development roadmap does not point back, and the six items the
  feature roadmap lists as "remain planned" are exactly the six unchecked Phase 4 items in
  the development roadmap. Both were last updated the same day, 2026-07-13.

**The one real trap** is that "Phase 4" names two different things: *Smarter detection* in
the feature roadmap, *Operational Visibility And Control* in the development roadmap. When
the feature roadmap says "the active phase is Phase 4" it means the development roadmap's
Phase 4. Cite the document name whenever citing a phase number.

No merge, rename or deletion is warranted. Nothing needs deciding here.
