"""
Terasploit Framework (c) 2026

Author:          4steroth
License:         BSD-3-Clause
Path:            teralibs/tsf/core/base/payload.py
"""

from teralibs.tsf.core.handler.constants import Handler
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


# Payload type constants

#: Fully self-contained single-delivery payload.
SINGLE = "single"

#: First-stage stub; opens a channel and waits for the companion stage.
STAGER = "stager"

#: Second-stage payload delivered over the stager's channel.
STAGE = "stage"

#: Wraps a single payload to run it via a different transport.
ADAPTER = "adapter"

#: Frozenset of all recognised payload type strings.
ALL_PAYLOAD_TYPES = frozenset({SINGLE, STAGER, STAGE, ADAPTER})

# Payload Handler

PayloadHandler = Handler


# Everything in the module
__all__ = [
    # Payload types
    "ADAPTER",
    "ALL_PAYLOAD_TYPES",
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
    # Payload types
    "SINGLE",
    "STAGE",
    "STAGER",
    # Payload Handler
    "PayloadHandler",
]


class Payload(Base):
    """Base class for Terasploit payload modules."""

    # Handler classification

    #: Handler storage
    HANDLER = None

    # Payload classification

    #: One of SINGLE / STAGER / STAGE / ADAPTER.
    PAYLOAD_TYPE = SINGLE

    #: Dotted stage path for stager modules (e.g. "linux.x64.shell").
    STAGE_PATH = ""

    #: Python import path of the wrapped single for adapter modules.
    WRAPPED_PAYLOAD_PATH = ""

    # Target specification

    #: Target architectures using ARCH_* constants.
    ARCH = [ARCH_ALL]

    #: Target platforms using PLATFORM_* constants.
    PLATFORM = [PLATFORM_ALL]

    # Size and encoding constraints

    #: Hard upper limit on generated payload size in bytes; None = no limit.
    MAX_SIZE = None

    #: Pre-computed byte length of what generate() produces.
    #: Used by adapters to size-check a wrapped single before generation.
    #: Set to -1 when the size is dynamic or unknown.
    CACHED_SIZE = -1

    #: Bad-character set in \\xNN or hex-pair notation; "" = no filter.
    BADCHARS = ""

    #: Keys of options shown by show options.
    OPTIONS = []

    #: Keys of options shown by show advanced.
    ADVANCED_OPTIONS = []

    #: Keys of options shown by show evasion.
    EVASION_OPTIONS = []

    #: Payload misc config.
    STAGE_ENCODING = False
    STAGER_CONF = {}
    SAVE_REGISTERS = None
    STAGE_PREFIX = ""

    def generate(self, ctx) -> bytes | str:
        """
        Return the payload bytes to be delivered by the exploit module.
        """
        return b""

    def generate_stage(self, ctx) -> bytes:
        """
        Return the stage bytes sent by the framework over the stager channel.
        """
        return b""

    def compatible(self, cached_size) -> bool:
        """
        Return whether this payload is compatible with the calling adapter.
        """
        return True
