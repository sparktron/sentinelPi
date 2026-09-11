# ADR-0002: Active response is fail-closed on its own audit record

- **Date:** 2026-07-12 (decision) · record written 2026-09-11
- **Status:** accepted
- **Deciders:** Dylan Sparks
- **Retroactive record.** Contemporary with commits `a3f63c5` "Persist responder action
  history", `e7a5b49` "Expire timed firewall responses" and `0295621` "Fail closed on audit
  persistence errors"; only the record is late. Reconstructed from `docs/CODE_REVIEW.md`
  (Phase 1 and Phase 3 status, 2026-07-12), `docs/DEVELOPMENT_ROADMAP.md` Phase 1 and Phase 3
  exit criteria, `docs/FEATURE_ROADMAP.md` Phase 2, and `CHANGELOG.md` `[Unreleased] → Fixed`.

## Context

The responder layer can change the real world: DROP rules in `iptables`/`nftables`, a domain
sinkholed at the resolver, a gateway ARP entry re-pinned, an operator-supplied kill-switch
command. From Phase 2 onward these were gated by configuration — master switch, dry-run,
approval, per-category allowlist — and that gating was always the design.

What the 2026-07-12 review exposed was a different failure mode. The gates all lived in memory
and in config; the *record* of what had been planned, approved and executed did not reliably
survive. Two concrete consequences:

- a timed firewall block whose expiry lived only in process memory outlived the process, leaving
  a rule in place with nothing tracking it;
- a SQLite write failure — a full SD card, a corrupt database, a permissions change — could
  leave the responder happily executing actions with no durable evidence that they happened.

A network monitor that silently blocks traffic it cannot account for is worse than one that does
not block at all, because the operator's next debugging session starts from a false premise.

## Decision

The durable record is a precondition for the action, not a byproduct of it.

1. **Both the plan and the pre-execution intent are persistence gates.** If either row cannot be
   written, the responder does not run. `tests/test_response_persistence.py::
   test_response_does_not_execute_without_durable_audit_plan` states this directly.
2. **Alert dispatch itself is fail-closed the same way.** If the source alert row cannot be
   saved, dispatch stops before notification, scoring, correlation and response — so an
   unpersisted alert can never drive an armed response.
3. **Degradation is durable and loud.** `DurablePersistenceHealth` records the degraded state in
   `app_state` with a `CRITICAL` log, so it survives the restart that would otherwise hide it,
   and it surfaces through `/api/status`.
4. **Timed actions reconcile after a restart.** Expiry is persisted with rule markers; on
   startup `ResponderManager` rehydrates pending actions and removes blocks whose time has
   passed, for both the `iptables` and `nftables` backends.
5. **Responders describe; the manager decides.** A responder returns a `ResponderAction`; only
   `ResponderManager` evaluates the ladder, writes the ledger and executes. The gates therefore
   cannot be bypassed by adding a responder.

## Alternatives considered

| Option | Why not |
|---|---|
| Execute first, persist afterwards (best effort) | The exact window that produces unattributable firewall rules. The whole point is that the record cannot lag the action |
| Log to the JSON alert log instead of the database | The log is rotated and is not queried on startup; nothing could reconcile an expired block from it |
| Keep timed expiry in memory with a timer thread | Does not survive restart or crash — which is precisely when a stale DROP rule is most damaging and least expected |
| Fail *open*: act anyway when persistence fails, on the argument that containing a live threat beats bookkeeping | Rejected. The tool is opt-in, defensive, and off by default; an operator who cannot see what it did cannot trust or undo it. Availability of the response is worth less than accountability for it |
| Put the gates in each responder | Four copies of the same safety logic, and every new responder is a chance to omit one |

## Consequences

- A degraded database means active response stops, not that it proceeds unrecorded. On a Pi with
  a dying SD card — the expected hardware failure — the tool goes quiet on responses and says so
  rather than acting blind.
- Responder tests must supply a real (temporary) database; a fake store that always succeeds
  would not exercise the gate that matters.
- Restart is a first-class path, not an edge case: pending approvals rehydrate into the dashboard
  queue and expired blocks reconcile, so `systemctl restart` is safe while actions are in flight.
- The audit ledger is queryable — `/api/responses/recent` and the response-action history on the
  host page are reads of the same rows the gate requires.

## Revisit if

A responder is added whose action must be taken within a latency budget shorter than a synchronous
SQLite write, or the storage layer moves off SQLite and the "write then act" ordering has to be
re-derived for the new engine.
