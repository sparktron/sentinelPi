# Current Status

**Updated:** 2026-09-11 · **Branch:** `master` · **Commit:** `e54e64b`

## Objective

A defensive network anomaly monitor that runs unattended on a Raspberry Pi: it baselines normal
traffic, reports deviations in plain language, and — only when explicitly armed — can respond.
Python package under `src/sentinelpi/`, deployed by systemd or Docker on the Pi itself.

## Current state

- **The branch situation recorded in the previous revision of this file is resolved.**
  `codex/phase-0-and-1` was merged into `master` as `e54e64b` (2026-08-30, a merge of `f3fe6f3`
  and `fa3b377`). `git rev-list --left-right --count master...origin/codex/phase-0-and-1` now
  reports `3 0` — nothing on that branch is missing from `master` — and
  `master...origin/master` reports `0 0`, so `master` is pushed. The whole 2026-07-12/13
  review-correction programme (`ea61cbf` → `2065daa`) is now on `master` and inside CI's trigger
  scope.
- 65 modules under `src/sentinelpi/`; 55 test files containing 466 `def test_` definitions,
  which collect and run as 476 tests.
- Version metadata is `1.0.0` and `v1.0.0` is still the only tag; `git describe` reports
  `v1.0.0-24-ge54e64b`. Everything since sits under `[Unreleased]` in `CHANGELOG.md` — the
  release is 24 commits behind the code.
- `.github/workflows/ci.yml` runs compileall, ruff, mypy and coverage-gated pytest on Python
  3.10/3.11/3.12, plus a separate packaging smoke job, on push/PR to `master`.
- `docs/` holds the operator set (`configuration_guide.md`, `systemd_setup.md`,
  `troubleshooting.md`, `threat_model.md`, `security_considerations.md`), `CODE_REVIEW.md`, the
  two roadmaps, and — new in this pass — `ARCHITECTURE.md`, `VALIDATION.md` and `decisions/`.
- Working tree at the time of writing: only this documentation pass is uncommitted. No tracked
  source file is modified.

## Active work

Phase 4, "Operational Visibility And Control", in `docs/DEVELOPMENT_ROADMAP.md`. Its first
checkpoint — the runtime component/capability registry that drives event and poll routing and
reports lifecycle state through preflight and `/api/status` — shipped in `ca0e486`. Six items
under that phase remain unchecked: per-detector baseline readiness and reset/freeze controls,
per-sensor/exporter credentials with identity binding, sanitized PCAP/flow fixtures, unified
trust/whitelist/mute policy, notification delivery tracking, delivered scheduled reports.

## Next

1. **Decide what to do about the ruff range** (see Known problems). The lint gate currently
   depends on which ruff release the runner resolves; pinning the tool or selecting an explicit
   rule set are both defensible, and neither was chosen here.
2. **Perform the on-device procedure in `docs/VALIDATION.md` at least once.** There is no Pi
   evidence for this project at all, and that is now written down rather than assumed.
3. Continue the remaining Phase 4 items in `docs/DEVELOPMENT_ROADMAP.md`, and consider cutting
   a release — 24 commits of correctness work are unreleased.

## Blockers

None for host-side work: the full toolchain installs and the whole gate runs on this host (see
Validation state). The previous revision of this file recorded a broken in-repo `venv/` as a
blocker; that venv is not present in this checkout and a clean one built without incident.

On-device validation is blocked only by hardware availability — no Raspberry Pi is reachable
from this host.

## Known problems

- **The lint gate is not reproducible as declared.** `requirements-dev.txt` declares
  `ruff>=0.15.0,<1.0`, and `[tool.ruff]` in `pyproject.toml` sets only `target-version` and
  `line-length` — no `lint.select` — so the gate is whatever default rule set the resolved
  release ships. Measured on this commit, on this tree, 2026-09-11:

  | ruff | `ruff check src tests` | exit |
  |---|---|---|
  | 0.15.0 | `All checks passed!` | 0 |
  | 0.15.4 | `All checks passed!` | 0 |
  | 0.16.0 | `Found 902 errors` | 1 |
  | 0.16.7 | `Found 902 errors` | 1 |

  The 902 are almost entirely default-rule-set expansion, not new defects: 379 `UP006`, 122
  `UP045`, 121 `UP035`, 90 `I001`, 74 `BLE001`. CI installs from `requirements-dev.txt` on every
  run with no lockfile, so **the Lint step will fail on unchanged code the first time a GitHub
  runner resolves ≥ 0.16.0.** Not fixed here: changing a dependency or selecting a rule set is a
  project decision, and this was a documentation pass. `mypy` was checked at both ends of its
  own range (1.11.0 and 1.20.2) and is clean on both, so the problem is ruff-specific.
- **The installer and the project disagree about the minimum Python.** `scripts/install.sh`
  exits with "Python 3.11+ is required" (it scans `python3.12`, `python3.11`, `python3` and
  requires minor ≥ 11), while `pyproject.toml` declares `requires-python = ">=3.10"`, the README
  badge says 3.10+, and CI gates 3.10. `1965291` "Declare Python 3.10 support and complete
  release metadata" (2026-06-29) moved the declared floor without updating the installer. A
  3.10-only host that the project claims to support cannot be installed by the supported path.
- **The version string is dual-sourced and unguarded.** `pyproject.toml:version` and
  `src/sentinelpi/__init__.py:__version__` both say `1.0.0`, and no test compares them. The
  packaging smoke job prints `__version__` but never checks it against the wheel metadata.
- **The release tag lags the code by 24 commits.** Anyone installing `v1.0.0` from the GitHub
  release gets none of the Phase 0–4 correctness work.

## Validation state

All of the following ran on 2026-09-11 against commit `e54e64b` with a clean tracked tree, on
**x86_64 Linux** (kernel 6.18.44), in a fresh virtualenv built from `requirements.txt` +
`requirements-dev.txt` on **Python 3.10.20**. Resolved tool versions: **ruff 0.16.7**,
**mypy 1.20.2**, **pytest 8.4.2**, scapy 2.7.0, Flask 3.1.3.

| Check | Command | Result |
|---|---|---|
| Byte-compile | `python -m compileall -q src tests` | **passed**, exit 0, no diagnostics |
| Test suite + coverage | `pytest tests/ -q --cov=sentinelpi --cov-report=term-missing` | **passed** — 476 passed, 0 failed, in 22.30 s; total coverage **76.79 %**, above the `fail_under = 70` floor |
| Type check | `mypy` | **passed** — "no issues found in 65 source files" (also passed at the declared floor, mypy 1.11.0) |
| Lint | `ruff check src tests` | **failed on 0.16.7** (902 errors); **passed on 0.15.0 and 0.15.4**. See Known problems |
| Packaging smoke | `python -m build`; install the wheel into a clean Python 3.12 venv; `sentinelpi --version`; import; read the three packaged templates | **passed** — `SentinelPi 1.0.0`, `import OK 1.0.0`, `templates OK` |
| Config validation | `sentinelpi --config config/sentinelpi.yaml --check-config` (from the installed wheel) | **passed**, exit 0 — "Configuration OK", interfaces `['eth0']`, subnets `['192.168.1.0/24']`, dashboard 127.0.0.1:8888 |

This is the first recorded run in which the 476-test claim was actually reproduced; previous
revisions of this file carried it as documented-but-unverified.

**Not run:** `sentinelpi --check` (the active preflight that probes notifiers and responders —
it sends real test notifications and was not appropriate from this host), and every step of the
on-device procedure in `docs/VALIDATION.md`.

## Unverified

- **Everything about behaviour on real Pi hardware.** This host is x86_64, not a Raspberry Pi,
  and nothing in the repository or on this machine records an on-device run. A green host suite
  does not cover live scapy capture on a real NIC, promiscuous/mirror-port capture,
  `iptables`/`nftables` and `arp`/`ip neigh` responders, the DNS-sinkhole backends, the hardened
  systemd unit and its capability set, SD-card write behaviour, or sustained memory/CPU on a
  constrained board. **Host-green is not device-validated**, and no device validation is on
  record. `docs/VALIDATION.md` now states what would have to be demonstrated.
- **Any ARM result at all** — wheels, scapy, the Docker image (`FROM python:3.12-slim`).
- **GitHub state.** CI run history, the status of the merge on the remote, and release/artifact
  state were not queried from here; the branch conclusions above come from local refs only.
- **Real delivery of notifications and SIEM output.** `--check` proves the daemon can connect
  and send; nothing proves a collector parsed it.
- **Whether coverage is stable at 76.8 %** — a single run, not a distribution.

## Recent decisions

- `docs/decisions/0001-least-privilege-default-deployment.md` — default deployments grant
  `CAP_NET_RAW` only; `CAP_NET_ADMIN` comes solely from `systemd/active-response.conf` or
  `docker-compose.response.yml`. Retroactive record of commit `e0d0728` (2026-07-12).
- `docs/decisions/0002-active-response-is-fail-closed.md` — the durable audit record is a
  precondition for a responder action, not a byproduct. Retroactive record of `a3f63c5`,
  `e7a5b49` and `0295621` (2026-07-12).
- `docs/CODE_REVIEW.md` — repository-wide review dated 2026-07-12, corrective findings recorded
  closed 2026-07-13. Origin of the Phase 0–3 backlog; names the two critical wiring defects
  (`PortScanDetector` never registered, `DeviceTracker` alerts never dispatched) that isolated
  unit tests had missed.
- The corrective sequence as commits: `ea61cbf` → `e93bfde` → `a3f63c5` → `e7a5b49` → `ac36dae`
  → `01565c0` → `9f7ef0c` → `a826f49` → `41674db` → `e0d0728` → `e5baa9b` → `35d3e6e` →
  `9e53628` → `0b61849` → `0295621` → `9d3511c` → `15f1798` → `ca0e486` → `b9372be` → `2065daa`.
- `1d21347` / `f3fe6f3` (2026-07-26) — `AGENTS.md` is the single agent-instruction source;
  `CLAUDE.md` is one line, `@AGENTS.md`. The same change was committed on both sides of the
  branch, which is why the merge base carried a duplicate subject.

## Deep context

| Topic | Document |
|---|---|
| Current state | `docs/STATUS.md` (this file) |
| Agent instructions | `AGENTS.md` (invariants, commands, definition of done) |
| Architecture — threads, ownership, degradation | `docs/ARCHITECTURE.md` |
| Validation, including the unperformed on-device procedure | `docs/VALIDATION.md` |
| Decisions | `docs/decisions/` |
| Roadmap — active | `docs/DEVELOPMENT_ROADMAP.md` |
| Roadmap — feature history | `docs/FEATURE_ROADMAP.md` |
| Latest repository review | `docs/CODE_REVIEW.md` |
| Design constraints | `docs/threat_model.md`, `docs/security_considerations.md` |
| Configuration | `docs/configuration_guide.md` |
| Deployment | `docs/systemd_setup.md` |
| Operator troubleshooting | `docs/troubleshooting.md` |

### On the two roadmaps

They are a **sequence with a live document and a historical one**, not a conflict, and each file
says so itself.

- `FEATURE_ROADMAP.md` is the older, product-shaped roadmap ("evolve SentinelPi … into the
  protector of the whole network"), organised as Phase 0–6. Its own third paragraph states that
  it is retained as implementation history and that current work is tracked in
  `DEVELOPMENT_ROADMAP.md`.
- `DEVELOPMENT_ROADMAP.md` is the live one — created 2026-06-10, updated 2026-07-13, organised
  around the 2026-07-12 review. Phases 0–3 are marked complete with per-phase suite counts
  (408 → 418 → 443 → 469); Phase 4 is the only phase with unchecked boxes.
- The handoff is one-directional, and the six items the feature roadmap lists as "remain
  planned" are exactly the six unchecked Phase 4 items in the development roadmap.

**The one real trap** is that "Phase 4" names two different things: *Smarter detection* in the
feature roadmap, *Operational Visibility And Control* in the development roadmap. Cite the
document name whenever citing a phase number.
