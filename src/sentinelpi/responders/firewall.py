"""
responders/firewall.py - Block a malicious IP via iptables/nftables.

Quarantines a known-bad external host by inserting DROP rules in both
directions (outbound to it — stop exfil/C2 — and inbound from it). It only ever
*plans* commands; the ResponderManager decides whether to execute and, by
default, runs everything in dry-run.

Safety rails baked in:
- Never blocks a private/loopback IP or a whitelisted IP (you can't firewall
  your own gateway out of existence).
- Only handles alerts whose category is in ``auto_block_categories`` and whose
  severity meets ``auto_block_min_severity``.
- Requires both the master switch and ``firewall_block_enabled``.
"""

from __future__ import annotations

import logging
import re
from typing import Callable, List, Optional, Tuple

from .base import BaseResponder, ResponderAction
from ..models import Alert, Severity
from ..utils.network import is_private_ip, is_valid_ip

logger = logging.getLogger(__name__)

# Default command runner: returns (returncode, combined_output).
CommandRunner = Callable[[List[str]], Tuple[int, str]]


def _default_runner(argv: List[str]) -> Tuple[int, str]:
    import subprocess
    proc = subprocess.run(argv, capture_output=True, text=True, timeout=10)
    return proc.returncode, (proc.stdout + proc.stderr).strip()


class FirewallResponder(BaseResponder):
    """Inserts iptables/nftables DROP rules to quarantine a malicious IP."""

    def __init__(self, config, runner: Optional[CommandRunner] = None) -> None:
        super().__init__(config)
        self._runner = runner or _default_runner

    # ------------------------------------------------------------------ gating
    def can_handle(self, alert: Alert) -> bool:
        rc = self.config.response
        if not rc.firewall_block_enabled:
            return False
        if alert.category.value not in rc.auto_block_categories:
            return False
        try:
            if alert.severity < Severity(rc.auto_block_min_severity):
                return False
        except ValueError:
            logger.warning("Invalid auto_block_min_severity %r", rc.auto_block_min_severity)
            return False
        return self._blockable_ip(alert) is not None

    def _blockable_ip(self, alert: Alert) -> Optional[str]:
        """The external IP to block — related_host (the bad party) preferred."""
        for ip in (alert.related_host, alert.affected_host):
            if not ip or not is_valid_ip(ip):
                continue
            if is_private_ip(ip):
                continue
            if ip in self.config.whitelist_ips:
                continue
            return ip
        return None

    # -------------------------------------------------------------------- plan
    def plan(self, alert: Alert) -> Optional[ResponderAction]:
        ip = self._blockable_ip(alert)
        if ip is None:
            return None
        action = ResponderAction(
            responder=self.name,
            target=ip,
            description=f"Block {ip} ({self.config.response.firewall_backend}) — outbound and inbound DROP",
            duration_seconds=self.config.response.block_duration_seconds,
        )
        action.commands = self._build_commands(ip, action.action_id)
        action.rollback_commands = self._build_rollback_commands(ip)
        return action

    def _build_commands(self, ip: str, action_id: str = "") -> List[List[str]]:
        backend = self.config.response.firewall_backend
        if backend == "nftables":
            return [
                ["nft", "add", "rule", "inet", "filter", "output", "ip", "daddr", ip,
                 "drop", "comment", f"sentinelpi:{action_id}:output"],
                ["nft", "add", "rule", "inet", "filter", "input", "ip", "saddr", ip,
                 "drop", "comment", f"sentinelpi:{action_id}:input"],
            ]
        # default: iptables. -I inserts at the top so the DROP wins.
        return [
            ["iptables", "-I", "OUTPUT", "-d", ip, "-j", "DROP"],
            ["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"],
        ]

    def _build_rollback_commands(self, ip: str) -> List[List[str]]:
        if self.config.response.firewall_backend == "nftables":
            return []  # nftables rollback resolves rule handles dynamically.
        return [
            ["iptables", "-D", "OUTPUT", "-d", ip, "-j", "DROP"],
            ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
        ]

    # ----------------------------------------------------------------- execute
    def execute(self, action: ResponderAction) -> None:
        for argv in action.commands:
            try:
                code, output = self._runner(argv)
            except Exception as exc:  # runner blew up (binary missing, timeout, …)
                action.executed = True
                action.success = False
                action.error = f"{' '.join(argv)}: {exc}"
                logger.error("Firewall command failed: %s", action.error)
                return
            if code != 0:
                action.executed = True
                action.success = False
                action.error = f"{' '.join(argv)} -> exit {code}: {output}"
                logger.error("Firewall command non-zero exit: %s", action.error)
                return
        action.executed = True
        action.success = True
        logger.warning("Quarantined %s via %s.", action.target, self.config.response.firewall_backend)

    def expire(self, action: ResponderAction) -> Tuple[bool, str]:
        """Remove this action's firewall rules, treating already-absent rules as success."""
        if self.config.response.firewall_backend == "nftables":
            return self._expire_nftables(action)

        for delete_argv in action.rollback_commands:
            check_argv = list(delete_argv)
            check_argv[1] = "-C"
            try:
                check_code, _ = self._runner(check_argv)
                if check_code != 0:
                    continue  # already absent: idempotent reconciliation
                code, output = self._runner(delete_argv)
            except Exception as exc:
                return False, f"{' '.join(delete_argv)}: {exc}"
            if code != 0:
                return False, f"{' '.join(delete_argv)} -> exit {code}: {output}"
        return True, ""

    def _expire_nftables(self, action: ResponderAction) -> Tuple[bool, str]:
        for chain in ("output", "input"):
            marker = f"sentinelpi:{action.action_id}:{chain}"
            list_argv = ["nft", "-a", "list", "chain", "inet", "filter", chain]
            try:
                code, output = self._runner(list_argv)
            except Exception as exc:
                return False, f"{' '.join(list_argv)}: {exc}"
            if code != 0:
                return False, f"{' '.join(list_argv)} -> exit {code}: {output}"
            matching = next((line for line in output.splitlines() if marker in line), "")
            if not matching:
                continue  # already absent
            handle = re.search(r"# handle (\d+)", matching)
            if handle is None:
                return False, f"could not find nftables handle for {marker}"
            delete_argv = [
                "nft", "delete", "rule", "inet", "filter", chain, "handle", handle.group(1)
            ]
            code, delete_output = self._runner(delete_argv)
            if code != 0:
                return False, f"{' '.join(delete_argv)} -> exit {code}: {delete_output}"
        return True, ""
