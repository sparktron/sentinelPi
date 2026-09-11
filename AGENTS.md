# AGENTS.md

Guidance for coding agents working in this repository. Single source of truth;
`CLAUDE.md` imports it.

## What this is

SentinelPi — a Raspberry Pi network monitor that baselines normal traffic and
reports anomalies in plain language. Python package under `src/sentinelpi/`,
deployed via Docker or systemd on the Pi itself.

## Layout

- `src/sentinelpi/` — the package
- `config/sentinelpi.yaml` — runtime config
- `scripts/install.sh`, `setup_venv.sh`, `uninstall.sh` — host provisioning
- `docker-compose.yml`, `docker-compose.response.yml` — the second file adds the
  active-response stack; they are separate on purpose
- `docs/` — `threat_model.md`, `security_considerations.md`,
  `configuration_guide.md`, `systemd_setup.md`, `troubleshooting.md`

`docs/threat_model.md` and `docs/security_considerations.md` are the design
constraints for this project, not background reading. Consult them before
changing detection or response behavior.

## Commands

```bash
python -m compileall -q src tests
ruff check src tests
mypy
pytest tests/ -q --cov=sentinelpi --cov-report=term-missing
```

All four run in `.github/workflows/ci.yml` on Python **3.10, 3.11, 3.12**.
`mypy` is invoked bare — it reads its config from `pyproject.toml`, so don't
pass paths and assume the same result.

Deps are split: `requirements.txt` (runtime) and `requirements-dev.txt`.
`pyproject.toml` also exists — keep the three consistent when adding a dep.

## Target constraints

This runs on Raspberry Pi hardware, frequently a spare/older board.

- Assume constrained CPU and limited RAM. Packet-path code is hot — avoid
  per-packet allocation and avoid pulling in heavyweight deps for convenience.
- Assume the SD card is the storage medium. Avoid chatty writes; batch log and
  DB writes rather than flushing per event.
- The device is expected to run unattended for long periods. Any new background
  task needs a defined failure mode — no silent exception swallowing in the
  capture or analysis loop.

## Response actions

`docker-compose.response.yml` enables active response, which can modify network
state. Treat anything that blocks, drops, or reconfigures as destructive:
gate it behind explicit config, default it off, and confirm before extending
its scope.

## Changelog

`CHANGELOG.md` is maintained. Add an entry for user-visible changes —
detection behavior, config keys, deployment steps.

## Architecture

One process, many threads. Every input — scapy capture, `/proc/net` polling, conntrack /
NetFlow / filterlog flow ingest, honeypot — pushes onto one bounded `queue.Queue`
(`maxsize=50_000`); a single `EventRouter` thread drains it and fans each event out to every
event detector. Poll-driven detectors, threat-feed refresh, the maintenance loop and the
waitress dashboard each own their own thread. Everything a detector emits goes through
`AlertManager` (dedup → persist → correlate → enrich → notify), and only then, only if armed,
to `ResponderManager`.

`runtime_registry.component_manifest()` is the single ordered manifest of every input,
inventory component, detector, notifier, responder and service. Startup routing, `--check`
preflight and `/api/status` all derive from it — see `docs/ARCHITECTURE.md` for the thread and
ownership model, shutdown ordering and degradation behaviour. The README's "How it works"
covers the data-flow picture; it does not cover any of the above.

## Important invariants

These are the constraints you cannot infer from the code and will break by default. Each says
what goes wrong and whether a test guards it.

- **A new input/detector/notifier/responder must be added to `component_manifest()`**, not only
  wired in `main.py`. Startup event/poll routing is derived from the manifest, so a component
  missing from it is never routed, never reported by `/api/status`, and silently inert — which
  is exactly the C1/C2 class of defect the 2026-07-12 review found (`docs/CODE_REVIEW.md`).
  Guarded: `tests/test_runtime_registry.py`, `tests/test_phase0_wiring.py`.
- **Alert dispatch is fail-closed on persistence.** If the alert row cannot be saved, nothing
  downstream runs — no notification, scoring, correlation or response. A responder never
  executes without both a durable plan and a pre-execution intent record. Removing either gate
  produces unaudited real-world actions. Guarded: `tests/test_response_persistence.py`.
- **Default deployments grant `CAP_NET_RAW` only.** `CAP_NET_ADMIN` arrives solely through
  `systemd/active-response.conf` or `docker-compose.response.yml`. Never add it to
  `systemd/sentinelpi.service` or `docker-compose.yml`. Guarded by static assertions in
  `tests/test_deployment_safety.py`; rationale in `docs/decisions/0001-least-privilege-default-deployment.md`.
- **Every per-host/per-key map on the packet path must be bounded.** SYN dedup is 60 s /
  50 000 entries (`capture/packet_capture.py`), the correlator LRU-caps actors and expires
  cooldowns, the dedup cache is capped. Unbounded growth is invisible on a dev host and fatal
  on a Pi with 256 MB `MemoryMax`. Guarded: `tests/test_memory_bounding.py`.
- **Each `Database` instance owns its own thread-local connection namespace.** Do not share a
  connection across threads, or a thread-local across instances — two `Database` objects on one
  thread would otherwise close each other's connection. Guarded:
  `tests/test_db_migrations.py::test_database_instances_do_not_share_same_thread_connection`.
- **`SCHEMA_VERSION` (currently 12, `storage/database.py`) is bumped with every schema change
  and paired with a migration.** Reopening an older database must migrate, not fail; `--restore`
  refuses a newer-schema snapshot without `--force`. Guarded: `tests/test_db_migrations.py`.
- **The dashboard never accepts its token from the query string**, and refuses to bind a
  non-loopback host with no token. Restoring query-string auth leaks the credential into logs,
  history and `Referer`. Guarded: `tests/test_dashboard_auth.py`.
- **Trusted devices suppress only new-device and low-confidence learned-behaviour alerts** —
  never security or reputation detections. Trust is a live, locked, audited policy; configured
  trust cannot be removed at runtime. Guarded: `tests/test_device_trust.py`.
- **Threshold precedence is defaults → sensitivity profile → explicit `thresholds` values**, and
  an explicitly requested config that is missing or malformed is fatal rather than falling back
  to defaults. Guarded: `tests/test_config_validation.py`,
  `tests/test_phase2_runtime_options.py`.
- **The version string lives in two places** — `pyproject.toml:version` and
  `src/sentinelpi/__init__.py:__version__` — and **nothing guards that they agree.** The
  packaging smoke test prints `__version__` but never compares it to the wheel's metadata.
  Change both together.
- **`ruff>=0.15.0,<1.0` is an unpinned range and `[tool.ruff]` selects no rule set**, so the
  lint gate is whatever that release's default happens to be. Measured on this tree
  (commit `e54e64b`, 2026-09-11): ruff 0.15.0 and 0.15.4 → `All checks passed`; ruff 0.16.0 and
  0.16.7 → **902 errors** (`ruff check src tests`, exit 1), mostly `UP006`/`UP045`/`UP035`/`I001`.
  CI installs from `requirements-dev.txt` on every run, so the lint step fails on unchanged code
  the first time a runner resolves ≥ 0.16. Choosing between pinning the tool and selecting an
  explicit rule set is a project decision and has deliberately **not** been made here. `mypy`
  was checked at both ends of its range (1.11.0 and 1.20.2) and is clean on both.

## Validation requirements

`docs/VALIDATION.md` is the procedure. The short version: the four CI gates plus the packaging
smoke test are the host gate, and **host-green is not device-validated**. There is no on-Pi
evidence on record for live capture, the responders that shell out to `iptables`/`nftables`/
`arp`, the hardened systemd unit, or sustained memory behaviour on a constrained board. Any
change to capture, responders, deployment manifests or the systemd unit needs the on-device
section of that document performed and its evidence recorded in `docs/STATUS.md`.

## Security / safety constraints

- **Defensive only.** No exploitation, traffic injection, credential harvesting, MITM or
  persistence tooling, including in tests and fixtures. `docs/threat_model.md` and
  `docs/security_considerations.md` are the binding constraints, not background reading.
- **Responders are destructive.** Anything that blocks, drops, sinkholes or reconfigures stays
  off by default, dry-run when enabled, approval-gated when armed, and never targets private,
  loopback or whitelisted addresses. Do not widen a responder's default category/severity gate.
- Never log the dashboard token, SMTP/Twilio credentials, ntfy tokens or cluster shared keys.
- Collector ingest is untrusted input: keep the body ceiling, enum/timestamp validation and the
  bounded `extra` limits in `cluster_validation.py`, and keep the NetFlow exporter allowlist.
- Threat-feed and GeoIP/ASN lookups are optional network/file dependencies — degrade quietly,
  never fail the daemon.

## Definition of done

1. `python -m compileall -q src tests`, `ruff check src tests`, `mypy`, and
   `pytest tests/ -q --cov=sentinelpi --cov-report=term-missing` all pass locally; coverage stays
   at or above the `fail_under = 70` floor in `pyproject.toml`.
2. New behaviour is gated behind a config flag that defaults to off/safe, and the flag has a
   tested runtime effect — a documented switch that does nothing is a Phase 2 review finding.
3. Any new runtime component appears in `component_manifest()` with a wiring test.
4. `CHANGELOG.md` gets an entry for user-visible changes (detection behaviour, config keys,
   deployment steps).
5. `docs/STATUS.md` is updated — including what was *not* run.
6. A decision with real alternatives gets a record in `docs/decisions/`.

## Where to find deeper context

| Topic | Document |
|---|---|
| Current state | `docs/STATUS.md` |
| Roadmap — active | `docs/DEVELOPMENT_ROADMAP.md` (review-driven backlog; the live phase is Phase 4) |
| Roadmap — feature history | `docs/FEATURE_ROADMAP.md` (the original Phase 0–6 product roadmap, retained as implementation history; it hands off to the development roadmap) |
| Latest repository review | `docs/CODE_REVIEW.md` (2026-07-12, corrective findings closed 2026-07-13) |
| Architecture — threads and ownership | `docs/ARCHITECTURE.md` |
| Validation, including on-device | `docs/VALIDATION.md` |
| Decisions | `docs/decisions/` |
| Design constraints | `docs/threat_model.md`, `docs/security_considerations.md` |

The two roadmaps are a sequence, not competitors — `FEATURE_ROADMAP.md` says so in its
own opening and names `DEVELOPMENT_ROADMAP.md` as where current work is tracked. Note the
phase numbers are scoped per document: "Phase 4" means *Smarter detection* in the feature
roadmap and *Operational Visibility And Control* in the development roadmap.
