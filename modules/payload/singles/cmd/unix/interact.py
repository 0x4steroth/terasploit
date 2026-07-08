"""
Terasploit Framework (c) 2026

Author:          4steroth
License:         BSD-3-Clause
Path:            modules/payload/singles/cmd/unix/interact.py
"""

from teralibs.tsf.base.payload import ARCH_CMD, PLATFORM_UNIX, SINGLE, Payload, PayloadHandler


class TerasploitModule(Payload):
    """
    Interact with Established Connection.
    """

    NAME = "Unix Command, Interact with Established Connection"
    DESCRIPTION = "Interacts with a shell on an established socket connection"
    AUTHOR = ["hdm", "4steroth"]
    LICENSE = "BSD-3-CLAUSE"
    RANK = "normal"
    REFERENCES = ["MSF - cmd/unix/interact.rb"]

    PAYLOAD_TYPE = SINGLE
    HANDLER = PayloadHandler.FindShell

    CACHED_SIZE = 0

    ARCH = [ARCH_CMD]
    PLATFORM = [PLATFORM_UNIX]
