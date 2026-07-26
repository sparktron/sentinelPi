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
