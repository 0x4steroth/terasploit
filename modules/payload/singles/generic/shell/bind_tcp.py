"""
Terasploit Framework (c) 2026

Author:          4steroth
License:         BSD-3-Clause
Path:            modules/payload/singles/generic/shell/bind_tcp.py
"""

from teralibs.tsf.base.payload import ARCH_ALL, PLATFORM_ALL, SINGLE, Payload, PayloadHandler


class TerasploitModule(Payload):
    """
    Generic payload for shell session via bind tcp connection.
    """

    NAME = "Generic Bind Shell (Single)"
    DESCRIPTION = "Listen for a connection on the target and spawn a command shell."
    AUTHOR = "4steroth"
    LICENSE = "BSD-3-CLAUSE"
    VERSION = "1.0"
    RANK = "normal"
    REFERENCES = []

    # Payload configuration
    PAYLOAD_TYPE = SINGLE
    HANDLER = PayloadHandler.BindTCP

    CACHED_SIZE = 0
    MAX_SIZE = 4096

    ARCH = [ARCH_ALL]
    PLATFORM = [PLATFORM_ALL]

    OPTIONS = ["LPORT", "RHOST"]
