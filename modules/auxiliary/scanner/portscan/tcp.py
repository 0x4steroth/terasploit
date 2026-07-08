"""
Terasploit Framework (c) 2026

Author:          4steroth
License:         BSD-3-Clause
Path:            modules/auxiliary/scanner/portscan/tcp.py
"""

import random
import socket
import threading
import time

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
    TCP Port Scanner.

    Enumerate open TCP services by performing a full TCP connect on each port.
    This does not need administrative privileges on the source machine, which
    may be useful if pivoting.
    """

    NAME = "TCP Port Scanner"
    DESCRIPTION = (
        "Enumerate open TCP services by performing a full TCP connect on each port. "
        "Supports port ranges, multi-threaded concurrency, and delay jitter."
    )
    AUTHOR = ["hdm", "kris katterjohn", "4steroth"]
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
                    "Ports to scan (e.g. 22-25,80-110,110-900)",
                    self.otype.STRING,
                ),
                self.opt(
                    "TIMEOUT",
                    1000,
                    True,
                    "The socket connect timeout in milliseconds",
                    self.otype.INTEGER,
                ),
                self.opt(
                    "CONCURRENCY",
                    10,
                    True,
                    "The number of concurrent ports to check per host",
                    self.otype.INTEGER,
                ),
                self.opt(
                    "DELAY",
                    0,
                    True,
                    "The delay between connections, per thread, in milliseconds",
                    self.otype.INTEGER,
                ),
                self.opt(
                    "JITTER",
                    0,
                    True,
                    "The delay jitter factor (maximum value by which to +/- DELAY) in milliseconds.",
                    self.otype.INTEGER,
                ),
            ]
        )

    #: Set by stop() so run() can exit its loop cleanly on unload.
    _stopped: bool = False

    def run(self, ctx):
        """Perform the multi-threaded TCP connect scan across the requested port range."""
        self._stopped = False

        rhost = ctx.get_option("RHOST") or ""
        ports_raw = ctx.get_option("PORTS") or "1-10000"
        timeout_raw = ctx.get_option("TIMEOUT") or "1000"
        concurrency_raw = ctx.get_option("CONCURRENCY") or "10"
        delay_raw = ctx.get_option("DELAY") or "0"
        jitter_raw = ctx.get_option("JITTER") or "0"

        if not rhost:
            ctx.error("RHOST is not set.")
            return

        # Parse and validate numeric configuration options
        ports = self._parse_ports(ports_raw)
        if not ports:
            ctx.error(f"PORTS option validation failed: Invalid specification {ports_raw!r}")
            return

        try:
            timeout = int(timeout_raw)
            concurrency = int(concurrency_raw)
            delay_value = int(delay_raw)
            jitter_value = int(jitter_raw)
        except (TypeError, ValueError) as e:
            ctx.error(f"Option validation failed: Numeric parameters must be integers. Error: {e}")
            return

        if delay_value < 0 or jitter_value < 0:
            ctx.error("Option validation failed: DELAY and JITTER must be >= 0.")
            return

        ctx.info(f"Starting TCP port scan against {rhost} ({len(ports)} ports)")

        results = []
        print_lock = threading.Lock()

        # Batch process the ports array using the concurrency limit
        while len(ports) > 0 and not self._stopped:
            threads = []

            # Extract a chunk of ports up to the defined concurrency limit
            batch = [ports.pop(0) for _ in range(min(concurrency, len(ports)))]

            for port in batch:
                t = threading.Thread(
                    target=self._scan_port,
                    args=(
                        ctx,
                        rhost,
                        port,
                        timeout,
                        delay_value,
                        jitter_value,
                        results,
                        print_lock,
                    ),
                )
                threads.append(t)
                t.start()

            for t in threads:
                try:
                    # Keep join blocking brief to check for cancellation/stop flags periodically
                    while t.is_alive():
                        t.join(timeout=0.1)
                        if self._stopped:
                            break
                except KeyboardInterrupt:
                    ctx.error("Scan interrupted by user.")
                    self._stopped = True

        # Summary reporting block
        if results:
            ctx.info("\n--- Scan Results ---")
            for res in results:
                ctx.success(f"Host: {res[0]:<15} Port: {res[1]:<5} State: {res[2]}")
        else:
            ctx.info("Scan finished. No open ports detected.")

    def check(self, ctx):
        """Verify that the target host is alive before executing the full scan range."""
        rhost = self.DATASTORE.get("RHOST") or ""
        if not rhost:
            ctx.error("RHOST is not set.")
            return

        ctx.info(f"Checking reachability of {rhost} via a smoke test on port 80...")

        if self._tcp_connect_single(rhost, 80, timeout=5.0):
            ctx.success(f"{rhost} is reachable.")
        else:
            ctx.warning(
                f"{rhost} is not reachable on port 80 - verify network state or RHOST configuration."
            )

    def stop(self):
        """Signal run() loop and active processing threads to exit early."""
        self._stopped = True

    def _scan_port(self, ctx, ip, port, timeout_ms, delay_ms, jitter_ms, results, lock):
        """Executes a connection attempt against a single port from a thread worker."""
        if self._stopped:
            return

        self._add_delay_jitter(delay_ms, jitter_ms)

        is_open = self._tcp_connect_single(ip, port, timeout=(timeout_ms / 1000.0))

        if is_open:
            with lock:
                ctx.success(f"{ip}:{port} - TCP OPEN")
                results.append((ip, port, "open"))

    @staticmethod
    def _tcp_connect_single(host: str, port: int, timeout: float) -> bool:
        """Attempt a synchronous TCP handshake connection to a target."""
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return True
        except (OSError, TimeoutError):
            return False

    @staticmethod
    def _parse_ports(port_str: str) -> list:
        """Parses complex port formats (e.g., '21-25,80,443') into distinct integers."""
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
        """Applies an obfuscating or throttling delay before running network tasks."""
        if delay_ms <= 0 and jitter_ms <= 0:
            return

        low = max(0, delay_ms - jitter_ms)
        high = delay_ms + jitter_ms

        actual_delay = random.randint(low, high) if low < high else low
        if actual_delay > 0:
            time.sleep(actual_delay / 1000.0)
