"""
responders/arp_restore.py - Restore the trusted gateway MAC on ARP poisoning.

When the gateway's MAC appears to change (the classic man-in-the-middle setup),
this responder re-pins the *configured* gateway MAC as a static ARP entry so the
Pi keeps sending upstream traffic to the real gateway rather than the attacker.

It only ever acts when the operator has configured both ``network.gateway_ip``
and ``network.gateway_mac`` — that configured MAC is the ground truth we restore
to. Without it there's nothing trustworthy to pin, so the responder declines.

Backends:
- ``arp`` - ``arp -s <gw_ip> <gw_mac>`` (static entry).
- ``ip``  - ``ip neigh replace <gw_ip> lladdr <gw_mac> dev <iface>``.
"""

from __future__ import annotations

import logging
from typing import Callable, List, Optional, Tuple

from .base import BaseResponder, ResponderAction
from ..models import Alert, AlertCategory, Severity

logger = logging.getLogger(__name__)

CommandRunner = Callable[[List[str]], Tuple[int, str]]


def _default_runner(argv: List[str]) -> Tuple[int, str]:
    import subprocess
    proc = subprocess.run(argv, capture_output=True, text=True, timeout=10)
    return proc.returncode, (proc.stdout + proc.stderr).strip()


class ARPRestoreResponder(BaseResponder):
    """Re-pins the trusted gateway MAC as a static ARP entry on poisoning."""

    def __init__(self, config, runner: Optional[CommandRunner] = None) -> None:
        super().__init__(config)
        self._runner = runner or _default_runner

    # ------------------------------------------------------------------ gating
    def can_handle(self, alert: Alert) -> bool:
        rc = self.config.response
        if not rc.arp_restore_enabled:
            return False
        if alert.category != AlertCategory.ARP_ANOMALY:
            return False
        if not alert.extra.get("is_gateway"):
            return False
        try:
            if alert.severity < Severity(rc.arp_restore_min_severity):
                return False
        except ValueError:
            logger.warning("Invalid arp_restore_min_severity %r", rc.arp_restore_min_severity)
            return False
        # We need a configured ground-truth gateway IP+MAC to restore to.
        net = self.config.network
        return bool(net.gateway_ip and net.gateway_mac)

    # -------------------------------------------------------------------- plan
    def plan(self, alert: Alert) -> Optional[ResponderAction]:
        net = self.config.network
        gw_ip, gw_mac = net.gateway_ip, net.gateway_mac
        if not gw_ip or not gw_mac:
            return None
        commands = self._build_commands(gw_ip, gw_mac)
        return ResponderAction(
            responder=self.name,
            target=gw_ip,
            description=f"Pin trusted gateway MAC {gw_mac} for {gw_ip} ({self.config.response.arp_restore_backend})",
            commands=commands,
        )

    def _build_commands(self, gw_ip: str, gw_mac: str) -> List[List[str]]:
        if self.config.response.arp_restore_backend == "ip":
            iface = self.config.network.interfaces[0] if self.config.network.interfaces else "eth0"
            return [["ip", "neigh", "replace", gw_ip, "lladdr", gw_mac, "dev", iface]]
        return [["arp", "-s", gw_ip, gw_mac]]

    # ----------------------------------------------------------------- execute
    def execute(self, action: ResponderAction) -> None:
        for argv in action.commands:
            try:
                code, output = self._runner(argv)
            except Exception as exc:
                action.executed = True
                action.success = False
                action.error = f"{' '.join(argv)}: {exc}"
                logger.error("ARP restore command failed: %s", action.error)
                return
            if code != 0:
                action.executed = True
                action.success = False
                action.error = f"{' '.join(argv)} -> exit {code}: {output}"
                logger.error("ARP restore command non-zero exit: %s", action.error)
                return
        action.executed = True
        action.success = True
        logger.warning("Restored trusted gateway MAC for %s.", action.target)
