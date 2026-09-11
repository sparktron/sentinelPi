# Architecture — threads, ownership, and degradation

The README's [How it works](../README.md#-how-it-works) section is the data-flow picture
(inputs → detectors → alert manager → outputs) and its **Architecture & module map** block is
the per-package table. Neither is repeated here. This document covers what those cannot: which
threads exist, what each one owns, what state crosses a boundary, and how the daemon behaves
when a part of it fails.

## One process, many daemon threads

SentinelPi is a single Python process. `SentinelPi.start()` (`src/sentinelpi/main.py`) brings up
the threads below; all of them are `daemon=True` and all of them exit by observing one shared
`threading.Event` (`_stop_event`).

| Thread | Started by | Owns | Exits when |
|---|---|---|---|
| main | `main()` | `_maintenance_loop` — DB purge/vacuum, stats logging, watchdog ticks | `_stop_event` set by SIGTERM/SIGINT |
| `EventRouter` | first event source to come up | draining `_capture_queue`, fanning each event to every event detector | `_stop_event` |
| packet capture | `_start_packet_capture` | the scapy sniffer; pushes onto `_capture_queue` | `PacketCapture.stop()` |
| flow sources (conntrack / NetFlow / filterlog) | `_start_flow_ingest` | their own sockets/poll loops; push onto `_capture_queue` | per-source `stop()` |
| one per polling detector/inventory component | `_start_polling_threads` via `build_detector_thread` | calling `poll()` every `poll_interval` (30 s inventory, 60 s detectors) | `_stop_event` |
| `ThreatIntelRefresh` | `_start_threat_intel` | feed download + on-disk cache | `_stop_event` |
| honeypot | `_start_honeypot` | canary listening sockets | `HoneypotService.stop()` |
| dashboard | `_start_dashboard` | the waitress server | `DashboardServer.stop()` |

**The queue is the only wide boundary.** Inputs never touch detectors directly; they enqueue
onto a single bounded `queue.Queue(maxsize=50_000)` and the router does the fan-out. That is
why the event router is started by *whichever* source comes up first — flow ingest works with
scapy capture disabled entirely. It also means the queue depth is the system's backpressure
signal: the watchdog alerts on `queue_ratio >= monitoring.self_monitoring_queue_warn_ratio`
rather than on any per-detector metric.

**Detector exceptions never escape their thread.** Both the router loop and
`build_detector_thread` catch `Exception` per iteration, log it, and continue. One broken
detector degrades coverage; it does not stop the daemon. The cost is that a detector failing
every poll is only visible in the log and in `/api/status` activity counters — not as a crash.

## What the runtime registry is for

`runtime_registry.component_manifest(config)` returns one ordered list of
`ComponentDefinition`s covering every input, inventory component, detector, notifier, responder
and service, each with its `configured` flag, its routes (`event`, `poll`) and its poll
interval. Three consumers derive from that single list:

1. **startup** — what gets constructed, routed to the event router, and given a polling thread;
2. **`--check` preflight** (`config/preflight.py`) — the configured/disabled matrix the operator
   sees before starting;
3. **`/api/status`** — live `configured / ready / started / degraded / stopped` state plus
   activity counters and timestamps, which the dashboard health badge renders.

It exists because the 2026-07-12 review (`CODE_REVIEW.md` C1/C2) found detectors that had
implementations and passing unit tests but were never constructed by the service. A component
that is not in the manifest is not routed and not reported, so the manifest — not `main.py` —
is the place a new component is registered. `tests/test_runtime_registry.py` asserts that every
configured routed component is actually bound at startup.

## State that crosses a boundary

- **SQLite.** `Database` runs in WAL mode with **one connection per thread**, held in a
  `threading.local` that belongs to *that `Database` instance*. Two `Database` objects on one
  thread therefore do not share or close each other's connection. All writes are synchronous;
  the volume assumption is tens of events per minute, and batching matters because the storage
  medium is an SD card.
- **Baseline statistics.** Welford accumulators live in memory and are checkpointed; dirty state
  is flushed on graceful shutdown, and learning completion/readiness is persisted so a restart
  does not re-enter a full quiet period.
- **Responder ledger.** Plans, approvals, executions, results and timed-block expiries are rows,
  not memory. After a restart, `ResponderManager` rehydrates pending actions and reconciles
  expired `iptables`/`nftables` blocks.
- **Trust policy.** Device trust is a live, locked policy on `DeviceTracker` persisted by MAC
  with actor/timestamp audit history — not a config snapshot read at boot. Config-declared trust
  cannot be removed at runtime.
- **Persistence health.** `DurablePersistenceHealth` stores a degraded/recovered record in
  `app_state`, so a failure survives the restart that would otherwise hide it.

## Failure and degradation behaviour

The system is built to degrade in four distinct ways, and they are deliberately not the same:

| Situation | Behaviour |
|---|---|
| A detector raises | logged, loop continues, other detectors unaffected |
| Alert row cannot be persisted | **dispatch stops before** notification, scoring, correlation and response; persistence health goes durably degraded (`CRITICAL` log) |
| Responder plan or pre-execution intent cannot be persisted | the action does **not** execute — no unaudited real-world change |
| Optional dependency missing (GeoIP/ASN DB, scapy, auth log, sinkhole backend) | the feature quietly no-ops; `_log_capabilities` warns once at startup and `--check` reports it as degraded, but the daemon still runs |

Self-monitoring is a first-class component, not logging: the watchdog raises `SYSTEM` alerts for
dead managed worker threads, stale capture/flow streams, capture-queue saturation, low disk, and
threat-feed refresh failure or staleness, and publishes a `health` summary through `/api/status`
and the daily report.

## Shutdown ordering

`_shutdown()` is ordered on purpose and the order is load-bearing:

1. stop the inputs (packet capture, flow sources, honeypot) so nothing new enters the queue;
2. stop the dashboard server (it holds a socket and its own threads);
3. `join(timeout=5.0)` every registered thread, logging any that did not stop;
4. **flush dirty baseline state** — after the threads that mutate it have stopped;
5. close notifiers, draining their bounded queues;
6. close the database and mark every component stopped.

Flushing before the joins would race the poll threads; joining without first stopping the inputs
would block on a queue that is still being filled. The 5-second join is a bound, not a promise —
a thread that overruns is reported, and the process still exits.

## The safety ladder is architecture, not configuration

Response is gated at four independent points — master switch off, dry-run, approval required,
per-category auto-execute allowlist (README's *Active response — the safety ladder*) — and each
gate lives in `ResponderManager`, not in the individual responders. Responders only ever
*describe* an action. The manager decides whether it runs, records the intent first, and refuses
outright if that record cannot be written. A responder that executed its own action would bypass
the ledger, the approval queue and the persistence gate at once.

The capability split mirrors it at the OS layer: the passive deployment gets `CAP_NET_RAW` and
nothing more, and `CAP_NET_ADMIN` arrives only through an explicit override file
(`docs/decisions/0001-least-privilege-default-deployment.md`).
