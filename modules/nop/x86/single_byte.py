"""
Terasploit Framework (c) 2026

Author:          4steroth
License:         BSD-3-Clause
Path:            modules/nop/x86/single_byte.py
"""

from teralibs.tsf.base.nops import ARCH_X64, ARCH_X86, Nops


# The canonical x86 NOP opcode: XCHG EAX, EAX.
_NOP_BYTE = b"\x90"
_NOP_INT = 0x90


class TerasploitModule(Nops):
    """
    x86 / x64 single-byte NOP sled using ``\\x90``.

    Produces a repeating sequence of the single opcode 0x90 (XCHG EAX,
    EAX).  No registers are modified - XCHG EAX, EAX is a true no-op on
    both IA-32 and AMD64.
    """

    NAME = "x86 Single Byte"
    DESCRIPTION = (
        "Generates a NOP sled using the single-byte 0x90 (XCHG EAX, EAX) "
        "opcode.  Fails cleanly when 0x90 is a bad character."
    )
    AUTHOR = "4steroth"
    LICENSE = "BSD-3-CLAUSE"
    VERSION = "1.0"
    RANK = "normal"
    REFERENCES = []

    #: Valid on both IA-32 and AMD64 - 0x90 is a legal single-byte NOP
    #: in both ISAs.
    ARCH = [ARCH_X86, ARCH_X64]

    #: XCHG EAX, EAX has no register side-effects.
    SAVE_REGISTERS = []

    OPTIONS = []
    ADVANCED_OPTIONS = []
    EVASION_OPTIONS = []

    def can_avoid(self, badchars: frozenset[int]) -> bool:
        """
        Return False immediately when 0x90 is a bad byte.

        Unlike polymorphic sleds this module has no alternative encoding,
        so advertising avoidance capability it does not have would cause
        the caller to waste time trying.
        """
        return _NOP_INT not in badchars

    def generate_sled(self, size: int, badchars: frozenset[int]) -> bytes:
        """Return *size* repetitions of 0x90."""
        if _NOP_INT in badchars:
            raise ValueError(
                "Cannot generate x86 single-byte NOP sled: 0x90 is in the bad-character list."
            )

        return _NOP_BYTE * size
