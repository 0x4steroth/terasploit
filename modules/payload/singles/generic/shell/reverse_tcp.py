"""
Terasploit Framework (c) 2026

Author:          4steroth
License:         BSD-3-Clause
Path:            modules/payload/singles/generic/shell/reverse_tcp.py
"""

from teralibs.tsf.base.payload import ARCH_ALL, PLATFORM_ALL, SINGLE, Payload, PayloadHandler


class TerasploitModule(Payload):
    """
    Generic payload for shell session via reverse tcp connection.
    """

    NAME = "Generic Reverse Shell (Single)"
    DESCRIPTION = "Connect back to attacker and spawn a command shell."
    AUTHOR = "4steroth"
    LICENSE = "BSD-3-CLAUSE"
    VERSION = "1.0"
    RANK = "normal"
    REFERENCES = []

    PAYLOAD_TYPE = SINGLE
    HANDLER = PayloadHandler.ReverseTCP

    CACHED_SIZE = 0
    MAX_SIZE = 4096

    ARCH = [ARCH_ALL]
    PLATFORM = [PLATFORM_ALL]

    OPTIONS = ["LHOST", "LPORT"]
