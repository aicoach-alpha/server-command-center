"""Network collector.

Rates are computed from consecutive reads of the cumulative byte counters, so
no blocking sleep is involved - the previous sample is stored and the delta is
divided by the measured wall-clock delta.

Read-only: no network interface, route, or firewall state is ever modified.
"""

from __future__ import annotations

import socket
import time
from typing import Any

import psutil

# Interfaces that are real network paths. Docker bridges, veth pairs, loopback
# and tailscale are collected but classified separately so the "active link"
# logic never picks a virtual interface.
VIRTUAL_PREFIXES = ("docker", "br-", "veth", "virbr", "tun", "tap")
IGNORED = {"lo"}


def is_physical(iface: str) -> bool:
    if iface in IGNORED:
        return False
    if iface.startswith(VIRTUAL_PREFIXES):
        return False
    return True


def is_wifi(iface: str) -> bool:
    """Wireless interfaces start with 'wl' (wlp3s0, wlan0, ...)."""
    return iface.startswith("wl")


class NetworkCollector:
    def __init__(self) -> None:
        self._prev_net: dict[str, Any] | None = None
        self._prev_ts: float | None = None
        # Prime so the first sample has a baseline delta.
        psutil.net_io_counters(pernic=True)
        self._prev_net = psutil.net_io_counters(pernic=True)
        self._prev_ts = time.monotonic()

    @staticmethod
    def _default_route_iface() -> str | None:
        """Read the active default route interface from /proc/net/route.

        Cheapest possible method: no subprocess, no netlink parsing.
        Returns the interface with the lowest metric among `default` routes.
        """
        best: tuple[int, str] | None = None
        try:
            with open("/proc/net/route", "r", encoding="utf-8") as fh:
                next(fh, None)  # header
                for line in fh:
                    parts = line.split()
                    if len(parts) < 8:
                        continue
                    iface = parts[0]
                    dest_hex = parts[1]
                    gw_hex = parts[2]
                    flags = int(parts[3], 16)
                    metric = int(parts[6])
                    # RTF_UP | RTF_GATEWAY
                    if flags & 0x1 and flags & 0x2 and dest_hex == "00000000" and gw_hex != "00000000":
                        if best is None or metric < best[0]:
                            best = (metric, iface)
        except (OSError, ValueError, StopIteration):
            return None
        return best[1] if best else None

    @classmethod
    def _default_routes(cls) -> list[dict]:
        """All default routes, so the UI can show LAN + Wi-Fi failover state."""
        out: list[dict] = []
        try:
            with open("/proc/net/route", "r", encoding="utf-8") as fh:
                next(fh, None)
                for line in fh:
                    parts = line.split()
                    if len(parts) < 8:
                        continue
                    iface = parts[0]
                    dest_hex = parts[1]
                    flags = int(parts[3], 16)
                    metric = int(parts[6])
                    if flags & 0x1 and flags & 0x2 and dest_hex == "00000000":
                        out.append({"interface": iface, "metric": metric})
        except (OSError, ValueError, StopIteration):
            pass
        out.sort(key=lambda r: r["metric"])
        return out

    def collect(self) -> dict:
        net = psutil.net_io_counters(pernic=True)
        now = time.monotonic()
        elapsed = max(1e-6, now - (self._prev_ts or now))

        addresses = self._addresses()
        stats = self._stats()
        gateway = self._default_gateway()
        active_iface = self._default_route_iface()
        routes = self._default_routes()

        interfaces: list[dict] = []
        for name, counters in net.items():
            entry: dict[str, Any] = {
                "name": name,
                "physical": is_physical(name),
                "wireless": is_wifi(name),
                "is_default_route": name == active_iface,
                "rx_bytes_total": counters.bytes_recv,
                "tx_bytes_total": counters.bytes_sent,
                "rx_packets_total": counters.packets_recv,
                "tx_packets_total": counters.packets_sent,
                "rx_errors_total": counters.errin,
                "tx_errors_total": counters.errout,
                "rx_dropped_total": counters.dropin,
                "tx_dropped_total": counters.dropout,
                "address": {
                    "ipv4": self._choose_primary_address(name, addresses, gateway),
                    "mac": addresses.get(name, {}).get("mac"),
                    "all_ipv4": addresses.get(name, {}).get("ipv4s", []),
                },
                "state": self._link_state(name, stats),
            }

            prev = (self._prev_net or {}).get(name)
            if prev is not None:
                d_rx = max(0, counters.bytes_recv - prev.bytes_recv)
                d_tx = max(0, counters.bytes_sent - prev.bytes_sent)
                entry["rx_bytes_per_sec"] = round(d_rx / elapsed, 1)
                entry["tx_bytes_per_sec"] = round(d_tx / elapsed, 1)
                entry["rx_packets_per_sec"] = round(
                    max(0, counters.packets_recv - prev.packets_recv) / elapsed, 1
                )
                entry["tx_packets_per_sec"] = round(
                    max(0, counters.packets_sent - prev.packets_sent) / elapsed, 1
                )
            else:
                entry["rx_bytes_per_sec"] = 0.0
                entry["tx_bytes_per_sec"] = 0.0
                entry["rx_packets_per_sec"] = 0.0
                entry["tx_packets_per_sec"] = 0.0

            interfaces.append(entry)

        self._prev_net = net
        self._prev_ts = now

        interfaces.sort(key=lambda i: (not i["physical"], i["name"]))

        # Aggregate over physical NICs only: this is what the operator cares
        # about and excludes bridge/veth double counting.
        physical = [i for i in interfaces if i["physical"]]
        wifi = [i for i in interfaces if i["wireless"]]
        total_rx = sum(i["rx_bytes_per_sec"] for i in physical)
        total_tx = sum(i["tx_bytes_per_sec"] for i in physical)

        active_link = None
        if active_iface:
            match = next((i for i in interfaces if i["name"] == active_iface), None)
            if match:
                active_link = {
                    "interface": active_iface,
                    "kind": "wifi" if is_wifi(active_iface) else "lan",
                    "address": match["address"].get("ipv4"),
                    "state": match["state"],
                }

        return {
            "active_interface": active_iface,
            "active_link": active_link,
            "default_routes": routes,
            "lan": self._describe_link(physical, wifi, "lan"),
            "wifi": self._describe_link(physical, wifi, "wifi"),
            "totals": {
                "rx_bytes_per_sec": round(total_rx, 1),
                "tx_bytes_per_sec": round(total_tx, 1),
                "rx_bytes_total": sum(i["rx_bytes_total"] for i in physical),
                "tx_bytes_total": sum(i["tx_bytes_total"] for i in physical),
            },
            "interfaces": interfaces,
            "sample_interval_s": round(elapsed, 3),
        }

    @staticmethod
    def _describe_link(physical: list[dict], wifi: list[dict], kind: str) -> dict | None:
        candidates = [i for i in physical if (i["wireless"] if kind == "wifi" else not i["wireless"])]
        if not candidates:
            return {"interface": None, "kind": kind, "state": "absent", "address": None}
        primary = candidates[0]
        return {
            "interface": primary["name"],
            "kind": kind,
            "state": primary["state"],
            "address": primary["address"].get("ipv4"),
            "rx_bytes_per_sec": primary["rx_bytes_per_sec"],
            "tx_bytes_per_sec": primary["tx_bytes_per_sec"],
        }

    @staticmethod
    def _link_state(iface: str, stats: dict | None = None) -> str:
        if stats is None:
            try:
                stats = psutil.net_if_stats()
            except (OSError, RuntimeError):
                return "unknown"
        st = stats.get(iface)
        if st is None:
            return "absent"
        if not st.isup:
            return "down"
        # A wifi NIC with no carrier is administratively up but idle/standby.
        if getattr(st, "speed", 0) == 0 and iface.startswith("wl"):
            return "standby"
        return "up"

    @staticmethod
    def _stats() -> dict:
        try:
            return psutil.net_if_stats()
        except (OSError, RuntimeError):
            return {}

    @staticmethod
    def _addresses() -> dict[str, dict]:
        out: dict[str, dict] = {}
        try:
            for iface, addrs in psutil.net_if_addrs().items():
                ipv4s: list[str] = []
                mac = None
                for addr in addrs:
                    if addr.family == socket.AF_INET and addr.address:
                        ipv4s.append(addr.address)
                    elif addr.family == psutil.AF_LINK:
                        mac = addr.address
                out[iface] = {"ipv4s": ipv4s, "ipv4": ipv4s[0] if ipv4s else None, "mac": mac}
        except (OSError, RuntimeError):
            pass
        return out

    @staticmethod
    def _default_gateway() -> str | None:
        """Address of the active default gateway, used to pick the primary IPv4."""
        try:
            with open("/proc/net/route", "r", encoding="utf-8") as fh:
                next(fh, None)
                best: tuple[int, str] | None = None
                for line in fh:
                    parts = line.split()
                    if len(parts) < 8:
                        continue
                    flags = int(parts[3], 16)
                    if not (flags & 0x1 and flags & 0x2):
                        continue
                    if parts[1] != "00000000" or parts[2] == "00000000":
                        continue
                    metric = int(parts[6])
                    if best is None or metric < best[0]:
                        # /proc stores the gateway little-endian hex.
                        raw = bytes.fromhex(parts[2])
                        best = (metric, socket.inet_ntoa(raw[::-1]))
                return best[1] if best else None
        except (OSError, ValueError, StopIteration):
            return None

    @classmethod
    def _choose_primary_address(
        cls, iface: str, addresses: dict[str, dict], gateway: str | None = None
    ) -> str | None:
        """Pick the address to display for an interface.

        An interface can hold several IPv4 addresses, including failover aliases.
        Prefer an address on the same /24 as the active gateway and fall back to
        the first one found so a host alias does not become the primary display.
        """
        entry = addresses.get(iface) or {}
        ipv4s: list[str] = entry.get("ipv4s") or []
        if not ipv4s:
            return entry.get("ipv4")

        gateway = gateway if gateway is not None else cls._default_gateway()
        if gateway:
            gw_octets = gateway.split(".")
            for addr in ipv4s:
                parts = addr.split(".")
                if len(parts) != 4 or len(gw_octets) != 4:
                    continue
                if parts[:3] == gw_octets[:3]:
                    return addr
        return ipv4s[0]