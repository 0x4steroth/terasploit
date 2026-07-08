"""
Terasploit Framework (c) 2026

Author:          4steroth
License:         BSD-3-Clause
Path:            modules/payload/stagers/windows/x86/shell/reverse_tcp.py
"""

from teralibs.tsf.base.payload import (
    ARCH_X86,
    PLATFORM_WINDOWS,
    STAGER,
    Payload,
    PayloadHandler,
)
from teralibs.tsf.core.payload.windows.x86.reverse_tcp_x86 import ReverseTcpX86


class TerasploitModule(ReverseTcpX86, Payload):
    """Windows x86 reverse-TCP stager."""

    NAME = "Windows x86 Reverse TCP Stager"
    DESCRIPTION = "Connect back to the attacker (Windows x86)"
    AUTHOR = ["hdm", "skape", "sf", "4steroth"]
    LICENSE = "BSD-3-CLAUSE"
    VERSION = "1.1"
    RANK = "normal"

    REFERENCES = [
        "https://github.com/rapid7/metasploit-framework/blob/master/"
        "modules/payloads/stagers/windows/x86/reverse_tcp.rb",
        "https://github.com/rapid7/metasploit-framework/blob/master/"
        "lib/msf/core/payload/windows/x86/reverse_tcp.rb",
    ]

    PAYLOAD_TYPE = STAGER
    HANDLER = PayloadHandler.ReverseTCP

    # Companion stage: modules/payload/stages/windows/x86/shell.py
    STAGE_PATH = "windows.x86.shell"

    # Corrected size values to match standard Windows x86 stager bounds
    CACHED_SIZE = 297
    MAX_SIZE = 512

    ARCH = [ARCH_X86]
    PLATFORM = [PLATFORM_WINDOWS]

    STAGER_CONF = {"RequiresMidstager": False}
