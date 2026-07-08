"""
Terasploit Framework (c) 2026

Author:          4steroth
License:         BSD-3-Clause
Path:            teralibs/tsf/core/base/post.py
"""

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
from teralibs.tsf.pex.platform import (
    PLATFORM_AIX,
    PLATFORM_ALL,
    PLATFORM_ANDROID,
    PLATFORM_APPLE_IOS,
    PLATFORM_BSD,
    PLATFORM_CHROME,
    PLATFORM_CISCO,
    PLATFORM_FIREFOX,
    PLATFORM_FREEBSD,
    PLATFORM_HARDWARE,
    PLATFORM_HPUX,
    PLATFORM_IRIX,
    PLATFORM_JAVA,
    PLATFORM_JUNIPER,
    PLATFORM_LINUX,
    PLATFORM_MAINFRAME,
    PLATFORM_NETBSD,
    PLATFORM_NETWARE,
    PLATFORM_NODEJS,
    PLATFORM_OPENBSD,
    PLATFORM_OSX,
    PLATFORM_PERL,
    PLATFORM_PHP,
    PLATFORM_PYTHON,
    PLATFORM_RUBY,
    PLATFORM_SOLARIS,
    PLATFORM_UNIX,
    PLATFORM_WINDOWS,
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
    # Platforms
    "PLATFORM_AIX",
    "PLATFORM_ALL",
    "PLATFORM_ANDROID",
    "PLATFORM_APPLE_IOS",
    "PLATFORM_BSD",
    "PLATFORM_CHROME",
    "PLATFORM_CISCO",
    "PLATFORM_FIREFOX",
    "PLATFORM_FREEBSD",
    "PLATFORM_HARDWARE",
    "PLATFORM_HPUX",
    "PLATFORM_IRIX",
    "PLATFORM_JAVA",
    "PLATFORM_JUNIPER",
    "PLATFORM_LINUX",
    "PLATFORM_MAINFRAME",
    "PLATFORM_NETBSD",
    "PLATFORM_NETWARE",
    "PLATFORM_NODEJS",
    "PLATFORM_OPENBSD",
    "PLATFORM_OSX",
    "PLATFORM_PERL",
    "PLATFORM_PHP",
    "PLATFORM_PYTHON",
    "PLATFORM_RUBY",
    "PLATFORM_SOLARIS",
    "PLATFORM_UNIX",
    "PLATFORM_WINDOWS",
]


class Post(Base):
    """Base class for Terasploit post-exploitation modules."""

    NAME = ""
    DESCRIPTION = ""
    AUTHOR = ""
    LICENSE = ""
    VERSION = ""
    RANK = "normal"
    REFERENCES = []

    ARCH = [ARCH_ALL]
    PLATFORM = [PLATFORM_ALL]

    #: Session types this module is compatible with.
    #: Use ["shell"] for command-shell sessions, ["meterpreter"] for Meterpreter.
    #: An empty list means the module accepts any session type.
    SESSION_TYPES = []

    OPTIONS = []
    ADVANCED_OPTIONS = []
    EVASION_OPTIONS = []

    def run(self, ctx):
        """Execute the post module against the active session."""
