# ADR-0001: Default deployments grant CAP_NET_RAW only

- **Date:** 2026-07-12 (decision) · record written 2026-09-11
- **Status:** accepted
- **Deciders:** Dylan Sparks
- **Retroactive record.** The decision is contemporary with commit `e0d0728` "Default
  deployments to least privilege"; only the record is late. Reconstructed from
  `docs/DEVELOPMENT_ROADMAP.md` (Phase 2, "Configuration Truthfulness And Deployment Safety"),
  `docs/CODE_REVIEW.md` (Phase 2 status, 2026-07-12), `CHANGELOG.md` `[Unreleased] → Changed`,
  and the shipped manifests. No prose was invented for it.

## Context

SentinelPi needs `CAP_NET_RAW` to sniff packets, and `CAP_NET_ADMIN` to make the firewall and
ARP responders work. Before 2026-07-12 the default systemd unit and the default Compose file
granted both, because the same manifests served both the passive monitor and the active-response
deployment.

That put the far more dangerous capability on every install, including the overwhelmingly common
one: a passive sensor with `response.enabled: false`, which is the shipped default. The
2026-07-12 repository-wide review recorded this under deployment safety, alongside the finding
that several documented configuration switches had no runtime effect — the theme being that what
the deployment actually granted did not match what the operator had asked for.

The constraint that made it a decision rather than an obvious call: active response must stay
genuinely usable. Anyone arming it has already accepted a real-world side effect, and a scheme
that made arming painful or undocumented would push operators to run the whole daemon as root
instead, which is strictly worse.

## Decision

Default deployments grant `CAP_NET_RAW` and nothing else. `CAP_NET_ADMIN` is added only through
an explicit, separate override that the operator has to opt into by name:

- systemd — the drop-in `systemd/active-response.conf`, installed as
  `/etc/systemd/system/sentinelpi.service.d/active-response.conf`, which resets and re-declares
  both `AmbientCapabilities` and `CapabilityBoundingSet`;
- Docker — `docker-compose.response.yml`, layered explicitly:
  `docker compose -f docker-compose.yml -f docker-compose.response.yml up -d`.

The split is guarded by static assertions in `tests/test_deployment_safety.py`, so the default
manifests cannot regain `NET_ADMIN` without a test failing. The same commit made the
hosts-file sinkhole target default to the writable data directory, so arming a responder does
not also require hand-editing filesystem permissions.

## Alternatives considered

| Option | Why not |
|---|---|
| Keep both capabilities in the default manifests | The dangerous capability ends up on every passive install, including the default configuration that can never use it |
| One manifest, capability chosen by a config flag at runtime | systemd and Compose capability sets are fixed before the process reads its config; the daemon cannot grant itself a capability it was not given |
| Drop the capability at runtime after startup when response is disabled | Possible, but the privilege still exists during startup and the mechanism is invisible to an operator auditing the unit file. `systemctl show` telling the truth is the point |
| Run as root and rely on the config gate alone | Discards every other hardening directive in the unit (`NoNewPrivileges`, `ProtectSystem=strict`, the syscall filter) for one capability |
| Ship two full unit files / two Compose files | Duplicates ~60 lines of hardening directives that would then drift apart. An override that only states the difference cannot drift |

## Consequences

- The default install is auditable in one command: `systemctl show sentinelpi -p
  AmbientCapabilities -p CapabilityBoundingSet` must print exactly `cap_net_raw`. That is
  step 4 of `docs/VALIDATION.md`.
- Arming active response is now a two-part action — config *and* deployment override. An
  operator who sets `response.enabled: true` without installing the override gets responders
  that plan and log but fail to execute. This is a deliberate cost, and
  `docs/systemd_setup.md` documents it; the failure mode is visible rather than silent.
- The manifests are now a tested artifact, not documentation. Editing `docker-compose.yml` or
  `systemd/sentinelpi.service` to add a capability breaks the build.
- `/proc`-only deployments can go further and drop `NET_RAW` entirely by setting
  `monitoring.packet_capture_enabled: false` and removing the `cap_add` block.

## Revisit if

A responder is added that needs a capability neither set covers (for example `CAP_NET_BIND_SERVICE`
for a privileged honeypot port), or the project starts shipping a distribution package whose
packaging system expects a single canonical unit file.
