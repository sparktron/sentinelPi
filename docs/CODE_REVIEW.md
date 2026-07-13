# SentinelPi Repository-Wide Code Review

_Review date: 2026-07-12 · Scope: application code, tests, configuration, deployment,
operator documentation, and packaging. Phase 2 completion validated 2026-07-12._

## Executive Summary

SentinelPi has a clear modular architecture, useful type checking, and a substantial test suite.
The reviewed checkout passed all 405 tests as well as Ruff, mypy, and byte-code compilation.
The review found two critical runtime-wiring defects that made advertised detections inoperative
in the real service even though their isolated unit tests passed:

1. `PortScanDetector` was never instantiated or registered by `SentinelPi`.
2. `DeviceTracker` created new-device and ARP-change alerts, but its service loop never sent them
   to `AlertManager`.

**Phase 0 status (2026-07-12): resolved.** The service now registers `PortScanDetector` for event
and polling inputs, and all inventory polling runs through the standard alert-dispatch wrapper.
Three service-wiring regressions were added; the full suite now contains 408 tests.

**Phase 1 status (2026-07-12): resolved.** Baseline learning age and dirty checkpoints now survive
restarts; response plans/results/approvals/expirations have a durable ledger; timed iptables and
nftables blocks reconcile after restart; and watchdog status reports overall and per-feed
threat-intelligence refresh health. The full suite now contains 418 tests.

**Phase 2 status (2026-07-12): resolved.** Normal startup fails closed, profile overrides are
predictable, public monitoring switches are wired, default deployments use least privilege, and
NetFlow/IPFIX ingest has bounded exporter/domain trust state. The full suite now contains 443 tests.

The next most important work is Phase 3 resilience and policy consistency.

Severity legend: **Critical** = a core advertised security behavior is absent or bypassed in normal
operation; **High** = material detection, response, security, or operator-trust failure;
**Medium** = correctness, resilience, or maintainability problem with narrower impact;
**Low** = polish or defensive hardening.

## Findings

### Critical

#### C1. Port-scan detection was not wired into the running service — Resolved

**Original issue:** `PortScanDetector` had implementation and unit tests, but `main.py` neither
imported nor constructed it. It was absent from both the packet/flow event-detector list and the
polling list, so vertical scans and the detector's host-sweep logic were never evaluated.

**Evidence:** `src/sentinelpi/main.py:60-71`, `src/sentinelpi/main.py:198-210`,
`src/sentinelpi/main.py:405-424`, and `src/sentinelpi/main.py:521-530` versus
`src/sentinelpi/detectors/port_scan_detector.py`.

**Implemented change:** one shared `PortScanDetector` is instantiated and included in both
`_build_event_detectors()` and `_build_pollers()`. The service-wiring regression asserts both paths.

#### C2. DeviceTracker alerts were generated but never dispatched — Resolved

**Original issue:** `DeviceTracker.poll()` returned alerts and also appended them to
`_pending_alerts`. `run_forever()` discarded the return value, while the main service special-cased
the tracker instead of using the normal detector wrapper. Nothing consumed the pending buffer.

**Evidence:** `src/sentinelpi/inventory/device_tracker.py:92-134`,
`src/sentinelpi/inventory/device_tracker.py:387-392`, and `src/sentinelpi/main.py:521-544`.

**Implemented change:** `_start_polling_threads()` now drives every poller, including
`DeviceTracker`, through `build_detector_thread()`, which sends returned alerts to `AlertManager`.
The unused pending buffer was removed, and a regression proves tracker alerts reach the manager.

### High

#### H1. Every restart re-entered the full baseline learning period — Resolved

**Issue:** hourly statistics, destinations, and domains are rehydrated, but the learning clock is
always reset to process start. With the default 24-hour period, every service restart suppresses
connection spikes, unusual countries/hours, new admin pairs, host-profile anomalies, and some DNS
signals for another day. Frequent updates or crashes can keep a sensor permanently learning.

**Evidence:** `src/sentinelpi/baseline/engine.py:128-172` and calls to `baseline.is_learning` across
the connection, DNS, geo-country, active-hours, lateral-movement, and host-profile detectors.

**Implemented change:** schema v9 persists the learning epoch in `app_state`; upgrades seed it from
the oldest existing baseline observation. Restart tests prove mature baselines remain active.

#### H2. Firewall block duration was accepted but ignored — Resolved

**Issue:** `response.block_duration_seconds` is documented and validated, but firewall execution
only inserts permanent rules. No timer, expiry metadata, delete command, or startup reconciliation
exists. A configured one-hour quarantine can last until an operator manually removes the rule or
the firewall is rebuilt.

**Evidence:** `src/sentinelpi/config/manager.py:316-322` and
`src/sentinelpi/responders/firewall.py:73-117`.

**Implemented change:** successful firewall actions receive execution-relative expirations in the
durable action ledger. Reconciliation runs at startup and during maintenance; iptables deletes are
idempotent and nftables rules use persisted action markers to resolve handles after restart.

#### H3. Threat-intelligence refresh failures were recorded as successes — Resolved

**Issue:** `ThreatIntelService.refresh()` returns `False` when every fetch/cache write fails. The
refresh loop ignores that result and always records watchdog success unless an exception escapes.
The service can use stale or empty feeds indefinitely while `/api/status` reports healthy refreshes.

**Evidence:** `src/sentinelpi/intel/threat_feeds.py:231-256` and
`src/sentinelpi/main.py:549-570`.

**Implemented change:** the refresh loop now honors the service result and sends per-feed attempt,
success, error, age, and staleness state to the watchdog. Total and partial failures are covered.

#### H4. Several public configuration switches have no runtime effect — Resolved

**Issue:** the repository exposes and documents behaviors that are not implemented or not wired:

- `monitoring.dns_monitoring_enabled` never disables DNS capture/detection.
- `monitoring.active_discovery_enabled` and its interval are never scheduled.
- `monitoring.file_integrity_enabled` is only checked by preflight; no runtime hashing occurs.
- `reporting.daily_report_enabled/hour` and weekly equivalents are never scheduled or delivered;
  only an on-demand dashboard JSON helper exists.
- traffic baseline methods and the `TRAFFIC_SPIKE` category exist, but no runtime component reads
  interface counters or emits traffic-spike alerts.

These silent no-ops undermine operator trust because `--check-config` accepts them and the README
describes several as shipped.

**Evidence:** definitions in `src/sentinelpi/config/manager.py:168-195` and
`src/sentinelpi/config/manager.py:280-285`; no runtime references outside preflight/tests for the
listed settings; `BaselineEngine.record_traffic()`/`check_traffic_spike()` have no production caller.

**Implemented change:** DNS disable now changes both capture and detector routing; active discovery
feeds bounded ARP sweeps through inventory; file-integrity polling hashes configured files;
daily/weekly report periods are restart-safe; and interface byte counters drive traffic-spike
baselines. Unit and service-wiring regressions cover each runtime path.

#### H5. Default deployments grant more network privilege than passive capture needs — Resolved

**Issue:** the systemd unit and Docker Compose grant `CAP_NET_ADMIN` unconditionally even though
passive packet capture only needs `CAP_NET_RAW` and active response is disabled by default.
`CAP_NET_ADMIN` permits broad firewall, route, and interface changes, increasing impact if the
daemon or a dependency is compromised.

The default hosts-file sinkhole also conflicts with `ProtectSystem=strict`: only `/var/lib` and
`/var/log` are writable, while the configured sinkhole path is under `/etc/sentinelpi`. Thus the
service is simultaneously overprivileged at the network layer and unable to use its default
file-backed responder.

**Evidence:** `systemd/sentinelpi.service:15-20`, `systemd/sentinelpi.service:46-62`,
`docker-compose.yml`, and default `response.dns_sinkhole_hosts_file` in
`src/sentinelpi/config/manager.py:324-327`.

**Implemented change:** default systemd and Compose manifests grant `NET_RAW` only. Explicit
systemd/Compose active-response overrides add `NET_ADMIN`. The default hosts-file sinkhole now lives
under `/var/lib/sentinelpi`, and preflight verifies the configured target (or its parent) is
writable. Static manifest and preflight regressions cover the boundary.

#### H6. NetFlow/IPFIX ingestion has no exporter trust boundary — Resolved

**Issue:** when enabled, the UDP collector accepts datagrams from any source address and feeds them
directly into baselines and detectors. An untrusted LAN host can inject false flows, create alerts,
poison learned profiles, or consume memory through exporter/template churn. Template caches are
also keyed as `(exporter, 0)` even though the docstring promises exporter plus source/observation
domain, so template IDs can collide for multi-domain exporters.

**Evidence:** `src/sentinelpi/capture/flow_ingest.py:436-459` and
`src/sentinelpi/capture/flow_ingest.py:489-517`.

**Implemented change:** enabled collectors require an exporter IP/CIDR allowlist. NetFlow v9 source
IDs and IPFIX observation-domain IDs are included in LRU cache keys; exporter, domain, template, and
record counts are capped. Rejected, malformed, and cache-eviction counters are exposed on the
collector. Authenticated transport via a local collector/proxy remains a stronger optional layer.

### Medium

#### M1. Normal daemon startup does not validate configuration and explicit load errors fail open — Resolved

**Issue:** validation only runs for `--check-config`/`--check`. Normal startup constructs
`SentinelPi` directly from `load_config()`. A missing explicit path, malformed YAML, or non-mapping
document logs a warning/error and silently uses defaults. Unknown keys are ignored, so a typo can
pass `--check-config` while the intended control remains at its default.

**Evidence:** `src/sentinelpi/config/manager.py:454-533` and
`src/sentinelpi/main.py:846-870`.

**Implemented change:** explicit/env-config failures are fatal, permissive defaults remain only when
no config was requested, unknown keys report full paths, and normal startup validates before any
subsystem or logging side effects. Typo, missing-file, malformed-file, and normal-startup
regressions cover the boundary.

#### M2. Sensitivity profiles overwrite explicit threshold values — Resolved

**Issue:** after YAML merge, conservative/aggressive profiles hard-set six thresholds. Operators
cannot use a profile and then override one threshold, despite the sample config saying thresholds
can be overridden.

**Evidence:** `src/sentinelpi/config/manager.py:530-561` and the threshold comments in
`config/sentinelpi.yaml`.

**Implemented change:** configuration loading now applies defaults -> profile values -> explicit
YAML threshold overrides. Regressions prove an explicit value wins while unspecified thresholds
retain the selected profile, and the precedence is documented in the README.

#### M3. SYN-ACK packets are treated as connection initiations — Resolved

**Issue:** the BPF filter captures every TCP packet with SYN set, including SYN-ACK. The port-scan
detector checks only for `"S"`, not the absence of `"A"`. Once C1 is fixed, server replies can be
recorded as reverse connection attempts and can pollute scan and host-profile state.

**Evidence:** `src/sentinelpi/capture/packet_capture.py:84-90`,
`src/sentinelpi/capture/packet_capture.py:298-328`, and
`src/sentinelpi/detectors/port_scan_detector.py:48-57`.

**Implemented change:** the BPF and parser now accept TCP SYN without ACK only. A bounded capture
cache collapses retransmitted SYNs once per 5-tuple/60-second window before event routing, while the
port-scan detector also rejects synthetic SYN-ACK events. Regressions cover `S`, `SA`, retransmits,
expiry, and the cache ceiling.

#### M4. Incident-correlation actor maps can grow without bound — Resolved

**Issue:** each actor deque is capped at 500 events, but actors themselves are never evicted from
`_events`, and `_last_incident` is never pruned. Unique spoofed or forwarded actors therefore grow
both dictionaries for the life of the collector.

**Evidence:** `src/sentinelpi/alerts/correlator.py:49-56` and
`src/sentinelpi/alerts/correlator.py:70-106`.

**Implemented change:** periodic cleanup removes empty actor deques and expired cooldowns. A
configurable `correlation.max_actors` ceiling evicts least-recently-seen actors deterministically,
and `/api/status` exposes tracked state plus eviction/expiry counters. High-cardinality and
multi-window regressions cover the bounds.

#### M5. Database connection storage is global across Database instances — Resolved

**Issue:** module-level `_thread_local.conn` is not keyed by `Database` instance or path. Creating
two `Database` objects on the same thread can make the second reuse the first database's connection.
This is surprising in tests, maintenance commands, and future multi-database use.

**Evidence:** `src/sentinelpi/storage/database.py:33-34` and
`src/sentinelpi/storage/database.py:58-75`.

**Implemented change:** every `Database` now owns its own `threading.local()` namespace. A regression
writes distinct state to two database paths on one thread and proves closing one instance does not
close or redirect the other.

#### M6. Alert processing can execute a response after audit persistence fails

**Issue:** a failed `save_alert()` is logged, but notification, suspicion changes, active response,
and correlation continue, and `_handle_alert()` still returns `True`. An armed response can modify
the host without a durable alert record, weakening the audit trail and making retries ambiguous.

**Evidence:** `src/sentinelpi/alerts/manager.py:164-213`.

**Implemented change:** alert persistence is now a fail-closed boundary before scoring,
notification, correlation, or response. Failed dedup reservations are released for retry and are
counted separately from suppressed/dispatched alerts. Response plans and an `executing` transition
must both be durable before a command can run; approvals, rejections, and expiration also retain
their prior state when the required write fails. Both paths emit critical logs and store durable
degraded/recovered health in `app_state`, surfaced by the dashboard status payload after restart.

#### M7. Response approvals and action history disappeared on restart — Resolved

**Issue:** pending and recent response actions are in-memory collections only. A restart loses
pending approvals and the dashboard audit history, while already-applied firewall/sinkhole effects
may remain. This also blocks safe implementation of timed rollback.

**Evidence:** `src/sentinelpi/responders/manager.py:36-46` and
`src/sentinelpi/responders/manager.py:80-150`.

**Implemented change:** schema v10/v11 stores response plans, commands, rollback commands, status,
results, duration, and expiration timestamps. Pending actions bind to configured responders after
restart, and executed/rejected/expired states remain available in recent history.

#### M8. The dashboard “trust device” action does not reduce detector noise

**Issue:** the endpoint mutates a `Device` object and database flag, but detectors consult static
IP/domain/port whitelists, and `DeviceTracker` snapshots trusted IP/MAC sets at construction. The
route's docstring promises reduced noise without establishing a runtime suppression policy. It also
mutates the object returned by `get_device()` outside the tracker's lock.

**Evidence:** `src/sentinelpi/ui/dashboard.py:431-440` and trusted-set initialization/use in
`src/sentinelpi/inventory/device_tracker.py`.

**Implemented change:** dashboard trust/untrust now calls a locked `DeviceTracker` policy operation.
Trust is durable by device MAC, survives address changes/restarts, and appends actor/timestamp audit
events. Connection volume/destination, active-hours, host-profile, new-country, and new-device noise
consult the live policy; security and reputation detections remain active. Configured trust cannot
be removed through the dashboard and runtime trust has a matching untrust action.

#### M9. Baseline snapshots could lose the last nine samples at shutdown — Resolved

**Issue:** connection statistics persist only on every tenth update, and shutdown has no baseline
flush. A crash or clean stop between checkpoints loses recent state; lightly observed hour/day
buckets may never persist at all.

**Evidence:** `src/sentinelpi/baseline/engine.py:178-199` and `SentinelPi._shutdown()`.

**Implemented change:** connection baseline buckets are marked dirty, periodic ten-sample
checkpoints clear matching snapshots safely, and graceful shutdown flushes all remaining dirty rows
after worker threads stop and before SQLite closes.

### Low

#### L1. Forwarded alert parsing can turn authenticated malformed input into a 500

**Issue:** `alert_from_dict()` directly casts confidence with `float()` and converts `extra` with
`dict()`. Invalid authenticated collector payloads can raise instead of returning a structured 400.

**Required fix:** validate collector payloads with bounded sizes and typed field errors before model
construction. Reject invalid timestamps, confidence ranges, extra shapes, and oversized strings.

#### L2. Logging setup is not idempotent

**Issue:** each `SentinelPi` construction adds root handlers without checking existing handlers.
Repeated app construction in one process duplicates log output and keeps file descriptors open.

**Required fix:** mark/replace SentinelPi-owned handlers or configure logging once at the entrypoint;
add a repeated-initialization test.

## Recommended Feature Work

These additions follow directly from the defects and current architecture, in priority order:

1. **Runtime wiring manifest and capability status.** Maintain one registry describing every input,
   detector, notifier, and responder, and expose whether each is configured, started, degraded, and
   producing events. Use it to drive startup, preflight, tests, and `/api/status` so a component
   cannot be implemented yet silently absent.
2. **Durable response ledger and reconciliation.** Persist approvals, executions, expiry, rollback,
   and command output; reconcile firewall/DNS/ARP state after restart. This unlocks reliable timed
   quarantine and a real audit trail.
3. **Baseline lifecycle controls.** Persist learning completion, show sample readiness per detector,
   allow an operator to freeze/reset selected baseline dimensions, and detect stale or poisoned
   baselines.
4. **Authenticated sensor/flow identity.** Give each sensor/exporter a distinct credential and
   identity binding, add replay protection and payload limits, and stop relying on one shared key or
   unauthenticated UDP source addresses.
5. **Detection-quality fixtures from packet captures.** Add small sanitized PCAP/flow fixtures for
   SYN/SYN-ACK/retransmit behavior, DNS query/response direction, IPv6, UDP, NetFlow observation
   domains, and service-level wiring. Unit-generated dataclasses currently miss several integration
   failures.
6. **Operator policy management.** Turn trust/whitelist/mute into one durable policy model with
   audit history, expiry, preview of affected detectors, and UI/API support for undo.
7. **Reliable notification delivery.** Add retry with bounded exponential backoff, per-channel
   delivery status, queue-depth/drop metrics, and an optional dead-letter store for high/critical
   alerts.
8. **Scheduled reports that are actually delivered.** Build daily/weekly scheduling on the existing
   report payload, select delivery channels, persist last-run state, and handle timezone/DST and
   missed-run recovery.

## Suggested Fix Order

1. ~~C1 and C2 with service-level regression tests.~~ Completed 2026-07-12.
2. ~~H1, H2, and H3 for detection/response correctness across restarts.~~ Completed 2026-07-12.
3. H4 and M1 so configuration and documentation tell the truth.
4. H5, H6, M6, and M7 for privilege boundaries and response audit safety.
5. Remaining medium/low findings and feature work.

## Validation Performed

- Initial review: `python -m pytest -q` — **405 passed** on Python 3.10.12.
- Phase 0 implementation: `python -m pytest -q` — **408 passed** on Python 3.10.12.
- Phase 1 implementation: `python -m pytest -q` — **418 passed** on Python 3.10.12.
- `ruff check src tests` — passed.
- `mypy` — passed for the configured `src/` scope (58 source files).
- `python -m compileall -q src tests` — passed.
- Manual static trace of all production modules, service startup/shutdown wiring, public config
  fields, deployment manifests, responders, dashboard APIs, persistence, and tests.

The initial review changed documentation only. Phase 0 and Phase 1 implementation status and
validation were appended as the corrective work landed on 2026-07-12.
