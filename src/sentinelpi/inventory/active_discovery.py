"""Optional low-rate ARP discovery for configured local subnets."""

from __future__ import annotations

import ipaddress
import logging
from typing import Callable, List

from ..capture.proc_reader import ARPEntry
from ..config.manager import Config
from ..models import Alert
from .device_tracker import DeviceTracker

logger = logging.getLogger(__name__)

try:
    from scapy.layers.l2 import ARP, Ether
    from scapy.sendrecv import srp

    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


def discover_arp_entries(config: Config) -> List[ARPEntry]:
    """Return hosts that answer a bounded ARP sweep of configured IPv4 subnets."""
    if not SCAPY_AVAILABLE:
        return []

    entries: List[ARPEntry] = []
    for subnet in config.network.subnets:
        network = ipaddress.ip_network(subnet, strict=False)
        if network.version != 4:
            continue
        if network.num_addresses > 4096:
            logger.warning("Skipping active discovery for oversized subnet %s", subnet)
            continue
        for interface in config.network.interfaces:
            try:
                answered, _ = srp(
                    Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(network)),
                    iface=interface,
                    timeout=2,
                    inter=0.05,
                    retry=0,
                    verbose=False,
                )
            except (OSError, PermissionError) as exc:
                logger.warning("Active discovery failed on %s: %s", interface, exc)
                continue
            for _sent, received in answered:
                entries.append(
                    ARPEntry(
                        ip=str(received.psrc),
                        mac=str(received.hwsrc),
                        interface=interface,
                        flags="0x2",
                    )
                )
    return entries


class ActiveDiscovery:
    """Polling adapter that routes discovered hosts through DeviceTracker."""

    def __init__(
        self,
        config: Config,
        device_tracker: DeviceTracker,
        discover: Callable[[Config], List[ARPEntry]] = discover_arp_entries,
    ) -> None:
        self.config = config
        self.device_tracker = device_tracker
        self._discover = discover

    @property
    def name(self) -> str:
        return self.__class__.__name__

    def poll(self) -> List[Alert]:
        return self.device_tracker.process_entries(self._discover(self.config))
