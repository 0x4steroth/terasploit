"""
Terasploit Framework (c) 2026

Author:          4steroth
License:         BSD-3-Clause
Path:            teralibs/tsf/core/base/nops.py
"""

import dataclasses

from teralibs.tsf.core.module.base import Base
from teralibs.tsf.pex.arch import (
    ARCH_AARCH64,
    ARCH_ALL,
    ARCH_ARMBE,
    ARCH_ARMLE,
    ARCH_BASH,
    ARCH_CBEA,
    ARCH_CBEA64,
    ARCH_CMD,
    ARCH_JAVA,
    ARCH_LUA,
    ARCH_MIPS,
    ARCH_MIPS64,
    ARCH_MIPS64LE,
    ARCH_MIPSBE,
    ARCH_MIPSLE,
    ARCH_NODEJS,
    ARCH_PERL,
    ARCH_PHP,
    ARCH_PPC,
    ARCH_PPC64,
    ARCH_PPC64LE,
    ARCH_PPCE500V2,
    ARCH_PYTHON,
    ARCH_RUBY,
    ARCH_SPARC,
    ARCH_SPARC64,
    ARCH_TTY,
    ARCH_X64,
    ARCH_X86,
    ARCH_X86_64,
    ARCH_ZARCH,
)


# Everything in the module
__all__ = [
    # Architectures
    "ARCH_AARCH64",
    "ARCH_ALL",
    "ARCH_ARMBE",
    "ARCH_ARMLE",
    "ARCH_BASH",
    "ARCH_CBEA",
    "ARCH_CBEA64",
    "ARCH_CMD",
    "ARCH_JAVA",
    "ARCH_LUA",
    "ARCH_MIPS",
    "ARCH_MIPS64",
    "ARCH_MIPS64LE",
    "ARCH_MIPSBE",
    "ARCH_MIPSLE",
    "ARCH_NODEJS",
    "ARCH_PERL",
    "ARCH_PHP",
    "ARCH_PPC",
    "ARCH_PPC64",
    "ARCH_PPC64LE",
    "ARCH_PPCE500V2",
    "ARCH_PYTHON",
    "ARCH_RUBY",
    "ARCH_SPARC",
    "ARCH_SPARC64",
    "ARCH_TTY",
    "ARCH_X64",
    "ARCH_X86",
    "ARCH_X86_64",
    "ARCH_ZARCH",
]


@dataclasses.dataclass(slots=True)
class NopsResult:
    """
    Outcome of a single :meth:`Nops.generate_sled` call.
    """

    success: bool
    sled_bytes: bytes
    nop_name: str
    error: str = ""


class Nops(Base):
    """
    Base class for all Terasploit NOP sled modules.

    Subclasses must:
      1. Set the class-level metadata attributes.
      2. Override :meth:`generate_sled` to return a bytes object of the
         requested length that contains none of the *badchars*.

    The framework never calls :meth:`generate_sled` directly - callers
    should call :meth:`generate` which wraps the result in a
    :class:`NopsResult` and handles exceptions uniformly.
    """

    # Module identity

    #: Human-readable module name shown in the console.
    NAME: str = ""

    #: One-paragraph description of the NOP sled strategy.
    DESCRIPTION: str = ""

    #: Author handle or contact information.
    AUTHOR: str = ""

    #: SPDX license identifier, e.g. "BSD-3-CLAUSE".
    LICENSE: str = ""

    #: Semantic version string, e.g. "1.0".
    VERSION: str = ""

    #: Module reliability ranking.
    RANK: str = "normal"

    #: External references as [type, url] pairs.
    REFERENCES: list = []

    # Target constraint

    #: Target architectures.  Use the ARCH_* constants defined in this
    #: module.  An empty list means the sled is architecture-agnostic.
    ARCH: list = [ARCH_ALL]

    # Option lists

    #: Keys of options shown by show options.
    OPTIONS: list = []

    #: Keys of options shown by show advanced.
    ADVANCED_OPTIONS: list = []

    #: Keys of options shown by show evasion.
    EVASION_OPTIONS: list = []

    # Sled hints

    #: Registers this NOP sled preserves.
    #:
    #: Encoders and exploit writers may consult this list to choose a NOP
    #: module that does not clobber a register they depend on.  Set to an
    #: empty list when the sled has no register side-effects (e.g. a pure
    #: single-byte ``\x90`` sled on x86).
    SAVE_REGISTERS: list = []

    # Public API

    def generate(self, size: int, badchars: frozenset[int] | None = None) -> NopsResult:
        """
        Generate a NOP sled of *size* bytes and return a :class:`NopsResult`.

        This method wraps :meth:`generate_sled` so callers always receive a
        structured result regardless of whether the underlying implementation
        raises.
        """
        if badchars is None:
            badchars = frozenset()

        if size < 0:
            return NopsResult(
                success=False,
                sled_bytes=b"",
                nop_name=self.NAME,
                error=f"Requested sled size {size} is negative.",
            )

        try:
            sled = self.generate_sled(size, badchars)
        except Exception as exc:  # pylint: disable=broad-except
            return NopsResult(
                success=False,
                sled_bytes=b"",
                nop_name=self.NAME,
                error=str(exc),
            )

        # Validate that the implementation honoured the badchars constraint.
        hit = next((b for b in sled if b in badchars), None)
        if hit is not None:
            return NopsResult(
                success=False,
                sled_bytes=b"",
                nop_name=self.NAME,
                error=(f"generate_sled returned a sled containing bad byte 0x{hit:02x}."),
            )

        return NopsResult(success=True, sled_bytes=sled, nop_name=self.NAME)

    def can_avoid(self, badchars: frozenset[int]) -> bool:
        """
        Return True when this module *might* be able to avoid *badchars*.

        The default implementation always returns True - subclasses that
        use a fixed instruction encoding (e.g. a single-byte sled) should
        override this to return False when their fixed byte is in badchars.
        """
        return True

    def generate_sled(self, size: int, badchars: frozenset[int]) -> bytes:
        """
        Generate and return a NOP sled of exactly *size* bytes.

        Subclasses must override this method.  The returned bytes must:
          - be exactly *size* bytes long (subject to architecture alignment);
          - contain no bytes present in *badchars*;
          - be semantically equivalent to a no-operation on the target.

        Raise :class:`ValueError` with a descriptive message when the
        sled cannot be generated (e.g. NOP byte is a bad char).
        """
        raise NotImplementedError(f"{self.__class__.__name__} must implement generate_sled().")
