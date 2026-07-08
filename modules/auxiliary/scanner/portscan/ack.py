"""
Terasploit Framework (c) 2026

Author:          4steroth
License:         BSD-3-Clause
Path:            modules/auxiliary/scanner/portscan/ack.py
"""

import random
import time

# Leveraging scapy for core raw packet generation and network sniffing
from scapy.all import IP, TCP, send, sniff

from teralibs.tsf.base.auxiliary import (
    ARCH_X64,
    ARCH_X86,
    PLATFORM_LINUX,
    PLATFORM_UNIX,
    PLATFORM_WINDOWS,
    Auxiliary,
)


class TerasploitModule(Auxiliary):
    """
    TCP ACK Firewall Scanner.

    Maps out firewall rulesets with a raw ACK scan. Any unfiltered ports found
    indicate that a stateful firewall is not actively blocking/tracking traffic for them.
    """

    NAME = "TCP ACK Firewall Scanner"
    DESCRIPTION = (
        "Map out firewall rulesets with a raw ACK scan. Any "
        "unfiltered ports found means a stateful firewall is "
        "not in place for them."
    )
    AUTHOR = ["kris katterjohn", "4steroth"]
    LICENSE = "BSD-3-CLAUSE"
    VERSION = "1.0"
    RANK = "normal"
    REFERENCES = []

    ARCH = [ARCH_X86, ARCH_X64]
    PLATFORM = [PLATFORM_LINUX, PLATFORM_UNIX, PLATFORM_WINDOWS]

    OPTIONS = ["RHOST"]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.register_options(
            [
                self.opt(
                    "PORTS",
                    "22-25",
                    True,
                    "Ports to scan (e.g. 22-25,80,110-900)",
                    self.otype.STRING,
                ),
                self.opt(
                    "TIMEOUT",
                    "500",
                    True,
                    "The reply read timeout in milliseconds",
                    self.otype.INTEGER,
                ),
                self.opt(
                    "DELAY",
                    "0",
                    True,
                    "The delay between connections, per thread, in milliseconds",
                    self.otype.INTEGER,
                ),
                self.opt(
                    "JITTER",
                    "0",
                    True,
                    "The delay jitter factor (maximum value by which to +/- DELAY) in milliseconds.",
                    self.otype.INTEGER,
                ),
                self.opt(
                    "INTERFACE",
                    None,
                    False,
                    "The name of the interface to send/receive packets from",
                    self.otype.STRING,
                ),
            ]
        )

    #: Set by stop() so run() can exit its loop cleanly on unload.
    _stopped: bool = False

    def run(self, ctx):
        """Perform the TCP ACK firewall enumeration."""
        self._stopped = False

        rhost = ctx.get_option("RHOST") or ""
        ports_raw = ctx.get_option("PORTS") or "1-10000"
        timeout_raw = ctx.get_option("TIMEOUT") or "500"
        delay_raw = ctx.get_option("DELAY") or "0"
        jitter_raw = ctx.get_option("JITTER") or "0"
        iface = ctx.get_option("INTERFACE") or None

        if not rhost:
            ctx.error("RHOST is not set.")
            return

        ports = self._parse_ports(ports_raw)
        if not ports:
            ctx.error(f"PORTS option validation failed: Invalid specification {ports_raw!r}")
            return

        try:
            timeout_ms = int(timeout_raw)
            delay_value = int(delay_raw)
            jitter_value = int(jitter_raw)
        except (TypeError, ValueError) as e:
            ctx.error(f"Option validation failed: Numeric parameters must be integers. Error: {e}")
            return

        if delay_value < 0 or jitter_value < 0:
            ctx.error("Option validation failed: DELAY and JITTER must be >= 0.")
            return

        timeout_secs = timeout_ms / 1000.0

        ctx.info(f"Scanning firewall profiles against {rhost} via ACK sequences...")

        for dport in ports:
            if self._stopped:
                break

            sport = random.randint(1025, 65534)
            self._add_delay_jitter(delay_value, jitter_value)

            try:
                # 1. Construct the raw probe packet
                probe = IP(dst=rhost) / TCP(
                    sport=sport, dport=dport, flags="A", ack=random.randint(0, 0xFFFFFFFF)
                )

                # 2. Define the BPF sniffer filter matching expected inbound RST responses
                # equivalent to Metasploit's getfilter()
                bpf_filter = f"tcp and (tcp[tcpflags] & tcp-rst != 0) and src host {rhost} and src port {dport} and dst port {sport}"

                # 3. Fire out the probe packet
                send(probe, verbose=False, iface=iface)

                # 4. Sniff for the reply using the calculated timeout window
                replies = sniff(filter=bpf_filter, timeout=timeout_secs, count=1, iface=iface)

                if not replies:
                    # Filtered ports don't answer back to unsolicited ACKs
                    continue

                # Answering back with an RST means the path is UNFILTERED by stateful protections
                ctx.success(f"TCP UNFILTERED {rhost}:{dport}")

            except Exception as e:
                ctx.error(f"Error checking {rhost}:{dport} -> Exception: {type(e).__name__}: {e}")

    def check(self, ctx):
        """Verify reachability of target before committing to raw injection tasks."""
        rhost = self.DATASTORE.get("RHOST") or ""
        if not rhost:
            ctx.error("RHOST is not set.")
            return

        ctx.info(f"Checking baseline network routing to {rhost}...")

        # Simple scapy-based ping/check to see if host responds to any basic TCP traffic
        try:
            sport = random.randint(1025, 65534)
            probe = IP(dst=rhost) / TCP(sport=sport, dport=80, flags="A")
            bpf_filter = f"tcp and src host {rhost} and dst port {sport}"

            send(probe, verbose=False, iface=ctx.get_option("INTERFACE"))
            replies = sniff(
                filter=bpf_filter, timeout=2.0, count=1, iface=ctx.get_option("INTERFACE")
            )

            if replies:
                ctx.success(f"{rhost} is alive and actively answering raw TCP traffic.")
            else:
                ctx.warning(f"No response from {rhost} on baseline check. Scanning anyway...")

        except Exception as e:
            ctx.error(f"Check failed due to error: {e}")

    def stop(self):
        """Signal run() loop to exit early."""
        self._stopped = True

    @staticmethod
    def _parse_ports(port_str: str) -> list:
        """Parses complex Metasploit-style port definitions into lists."""
        ports = []
        try:
            for part in str(port_str).split(","):
                if "-" in part:
                    start, end = map(int, part.split("-"))
                    ports.extend(range(start, end + 1))
                else:
                    ports.append(int(part))
            return sorted(list(set(ports)))
        except (ValueError, TypeError):
            return []

    @staticmethod
    def _add_delay_jitter(delay_ms: int, jitter_ms: int):
        """Calculates and schedules execution intervals inside serialization loops."""
        if delay_ms <= 0 and jitter_ms <= 0:
            return

        low = max(0, delay_ms - jitter_ms)
        high = delay_ms + jitter_ms

        actual_delay = random.randint(low, high) if low < high else low
        if actual_delay > 0:
            time.sleep(actual_delay / 1000.0)
