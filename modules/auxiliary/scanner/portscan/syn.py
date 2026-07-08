"""
Terasploit Framework (c) 2026

Author:          4steroth
License:         BSD-3-Clause
Path:            modules/auxiliary/scanner/portscan/syn.py
"""

import random
import time

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
    TCP SYN Port Scanner.

    Enumerate open TCP services using a raw SYN scan. This "half-open"
    technique avoids completing the 3-way handshake.
    """

    NAME = "TCP SYN Port Scanner"
    DESCRIPTION = (
        "Enumerate open TCP services using a raw SYN scan. "
        "This is generally faster and stealthier than a full connect scan."
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
        """Perform the TCP SYN half-open scan."""
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

        timeout_secs = timeout_ms / 1000.0

        ctx.info(f"Starting TCP SYN scan against {rhost}...")

        for dport in ports:
            if self._stopped:
                break

            sport = random.randint(1025, 65534)
            self._add_delay_jitter(delay_value, jitter_value)

            try:
                # 1. Build SYN Probe Packet
                probe = IP(dst=rhost) / TCP(sport=sport, dport=dport, flags="S", window=3072)

                # 2. Filter for either a SYN/ACK (Open) or RST (Closed)
                # SYN/ACK is 0x12, RST is 0x04
                bpf_filter = f"tcp and (tcp[tcpflags] & (tcp-syn|tcp-ack|tcp-rst) != 0) and src host {rhost} and src port {dport} and dst port {sport}"

                # 3. Dispatch raw packet
                send(probe, verbose=False, iface=iface)

                # 4. Monitor for the specific TCP state change
                replies = sniff(filter=bpf_filter, timeout=timeout_secs, count=1, iface=iface)

                if replies:
                    response = replies[0]
                    # Check for SYN-ACK flags
                    if response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12:
                        ctx.success(f"TCP OPEN {rhost}:{dport}")
                        # In a real SYN scan, you'd ideally send an RST here to be polite
                        # and close the half-open connection on the target.
                    elif response.haslayer(TCP) and (response.getlayer(TCP).flags & 0x04):
                        # Port is closed (RST received)
                        pass

            except Exception as e:
                ctx.error(f"Error checking {rhost}:{dport} -> {type(e).__name__}: {e}")

    def check(self, ctx):
        """Verify reachability and raw packet injection capabilities."""
        rhost = self.DATASTORE.get("RHOST") or ""
        if not rhost:
            ctx.error("RHOST is not set.")
            return

        ctx.info(f"Testing baseline TCP SYN response from {rhost}...")

        try:
            sport = random.randint(1025, 65534)
            probe = IP(dst=rhost) / TCP(sport=sport, dport=80, flags="S")
            bpf_filter = f"tcp and src host {rhost} and dst port {sport}"

            send(probe, verbose=False, iface=ctx.get_option("INTERFACE"))
            replies = sniff(
                filter=bpf_filter, timeout=2.0, count=1, iface=ctx.get_option("INTERFACE")
            )

            if replies:
                ctx.success(f"{rhost} is alive and responding to SYN probes.")
            else:
                ctx.warning(f"No response from {rhost} on baseline check. Scanning anyway...")
        except Exception as e:
            ctx.error(f"Check failed due to error: {e}")

    def stop(self):
        """Signal run() loop to exit early."""
        self._stopped = True

    @staticmethod
    def _parse_ports(port_str: str) -> list:
        """Parses complex port range syntax into integer lists."""
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
        """Calculates and applies randomized timing delays."""
        if delay_ms <= 0 and jitter_ms <= 0:
            return

        low = max(0, delay_ms - jitter_ms)
        high = delay_ms + jitter_ms

        actual_delay = random.randint(low, high) if low < high else low
        if actual_delay > 0:
            time.sleep(actual_delay / 1000.0)
