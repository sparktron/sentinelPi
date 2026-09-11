# Validation

How a change to SentinelPi is demonstrated correct. It exists because the host gate and the
device gate are not the same thing, and **only the host gate has ever been performed**. The
on-device procedure below has no recorded run — see [Known gaps](#known-gaps).

## What the automated suite covers

476 tests across 55 files in `tests/`, plus a packaging smoke test. They cover detector logic,
service-level wiring (that every advertised detector is constructed and routed), restart
behaviour of the baseline/response/trust ledgers, bounded memory helpers, schema migrations,
dashboard auth and rendering, collector payload validation, and static assertions on the
deployment manifests.

What it does **not** cover, and cannot:

- Live packet capture through scapy on a real NIC, promiscuous/mirror-port capture, or
  `CAP_NET_RAW` actually being sufficient for the capture path.
- Any responder's real side effect. `iptables`/`nftables` rules, `arp -s` / `ip neigh replace`,
  and the `hosts`/Pi-hole/Unbound sinkhole backends are exercised against fakes.
- The hardened systemd unit: `ProtectSystem=strict`, `SystemCallFilter=@system-service`,
  `MemoryMax=256M`, `CPUQuota=80%`, and the `ReadWritePaths` set.
- Sustained behaviour — memory growth, SD-card write volume, CPU headroom — over days on a
  constrained board.
- Real notification and SIEM delivery (SMTP, Twilio, ntfy, syslog collector, OTLP endpoint).
- Anything about ARM. Every recorded run has been on x86_64.

## Gate

The host gate is the four commands CI runs in `.github/workflows/ci.yml`, on Python **3.10,
3.11 and 3.12**, plus the separate packaging job:

```bash
python -m compileall -q src tests
ruff check src tests
mypy
pytest tests/ -q --cov=sentinelpi --cov-report=term-missing   # fail_under = 70
python -m build && pip install dist/*.whl && sentinelpi --version   # packaging smoke
```

CI triggers only on push/PR to `master`, so work on a side branch is ungated until it merges.

**The lint step is not reproducible as declared.** `requirements-dev.txt` pins
`ruff>=0.15.0,<1.0` and `[tool.ruff]` selects no rule set, so the gate is whatever default rule
set the resolved release ships. Measured on `e54e64b` (2026-09-11): 0.15.0 and 0.15.4 pass
clean; 0.16.0 and 0.16.7 report 902 errors. Record the ruff version with any run that claims the
lint gate passed. `mypy` was checked at 1.11.0 and 1.20.2 and is clean at both ends.

## Manual / on-device procedure

Run on the target class of hardware (Raspberry Pi 4 or newer, Raspberry Pi OS 64-bit), from a
clean install via `sudo bash scripts/install.sh`. Steps 1–6 are the passive deployment; 7–9 only
apply if active response is being armed.

| # | Check | Procedure | Pass criteria |
|---|---|---|---|
| 1 | Installer completes | `sudo bash scripts/install.sh` on a fresh image | Exits 0; `sentinelpi` user exists with `/usr/sbin/nologin`; `/opt/sentinelpi/venv`, `/etc/sentinelpi`, `/var/lib/sentinelpi`, `/var/log/sentinelpi` created |
| 2 | Capability granted, not root | `getcap $(readlink -f /opt/sentinelpi/venv/bin/python3)` | Prints `cap_net_raw+eip`; nothing runs as root |
| 3 | Config validates | `sudo -u sentinelpi /opt/sentinelpi/venv/bin/python -m sentinelpi.main --check-config` | Exit 0, echoes the configured interfaces/subnets |
| 4 | Service starts under the hardened unit | `sudo systemctl start sentinelpi; systemctl show sentinelpi -p AmbientCapabilities -p CapabilityBoundingSet` | Active (running); **both capability sets are exactly `cap_net_raw`** — no `cap_net_admin` |
| 5 | Capture is live on real traffic | `journalctl -u sentinelpi -f`, then generate traffic from another host | Capture thread reports events; `curl -H "Authorization: Bearer <token>" localhost:8888/api/status` shows a non-zero capture activity counter and a non-stale capture timestamp |
| 6 | Detection fires end to end | From another host on the LAN: `nmap -sS -p 1-200 <pi-ip>` | A `PORT_SCAN` alert appears in the dashboard and in `/var/log/sentinelpi/`, with the scanning host as the actor |
| 7 | Response stays inert by default | With `response.enabled: false`, trigger a threat-intel alert | Log records a planned action; `iptables -S` / `nft list ruleset` unchanged |
| 8 | Dry-run then approval | Set `response.enabled: true`, `dry_run: true`, observe for at least one day; then `dry_run: false`, `require_approval: true` | Dry-run executes nothing; armed actions appear PENDING in the dashboard queue and only apply after Approve |
| 9 | Timed block expires across a restart | Approve a firewall block with `block_duration_seconds` set, then `systemctl restart sentinelpi` | Rule is reconciled and removed at expiry, not left behind |
| 10 | Soak | Leave running ≥ 7 days on the target board | RSS stable and below `MemoryMax=256M` (no OOM kill in `journalctl`); capture queue ratio stays below the watchdog warn ratio; no `SYSTEM` watchdog alerts other than ones deliberately provoked |
| 11 | Baseline survives re-image | `sentinelpi --backup /media/usb/snap.db` while running, re-image, restore with `--restore` | Checksum/integrity verified; learned destinations, active hours and host profiles present after restart |
| 12 | Upgrade migrates | Start the new build against a database from the previous release | Schema migrates to `SCHEMA_VERSION`; no data loss; service starts |

## Evidence to record

A run counts only if all of it is captured, in `docs/STATUS.md` under **Validation state**:

- commit SHA, and whether the tree was clean;
- board model and OS release (`cat /proc/device-tree/model`, `/etc/os-release`), `uname -m`;
- Python version, **and the resolved `ruff` and `mypy` versions** (see Gate);
- the command run, its exit code and its counts (tests passed/failed, coverage percentage);
- for on-device steps: the `systemctl show` capability output, the relevant journal excerpt, and
  `/api/status` at the time of the check;
- for step 10: start and end timestamps and the RSS/queue readings at both ends.

State the three outcomes distinctly — **passed**, **failed**, **not run**. "The suite exists and
CI gates it" is not "it passed on this commit", and host-green is never device-validated.

## Known gaps

- **No on-device run has ever been recorded.** Every step in the table above is unperformed as
  of 2026-09-11. This is the single largest gap in the project: a network monitor whose entire
  value is on-hardware behaviour has only host evidence.
- **No ARM evidence at all.** Wheels, scapy behaviour, and timing on ARM are untested.
- **The installer and the project disagree about the minimum Python.**
  `scripts/install.sh` dies with "Python 3.11+ is required", while `pyproject.toml` declares
  `requires-python = ">=3.10"`, the README badge says 3.10+, and CI gates 3.10. A 3.10-only host
  the project claims to support cannot be installed by the supported installer. Not changed here
  — that is a code decision, not a documentation one.
- **The lint gate is version-dependent** (see Gate). Until the tool is pinned or a rule set is
  selected, a green lint result is only meaningful alongside the ruff version that produced it.
- **Docker deployment is unvalidated on ARM**; the image is built `FROM python:3.12-slim` and
  has only been exercised, if at all, on x86_64.
- **No SIEM/notification delivery has been proven against a real collector** — `--check` proves
  the daemon can connect and send, not that anything downstream parsed it.
