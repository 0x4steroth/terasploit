"""
Terasploit Framework (c) 2026

Author:          4steroth
License:         BSD-3-Clause
Path:            modules/evasion/windows/av_bypass/template.py
"""

from teralibs.tsf.base.evasion import Evasion
from teralibs.tsf.base.exploit import (
    ARCH_X64,
    ARCH_X86,
    PLATFORM_WINDOWS,
    Exploit,
)


class TerasploitModule(Exploit, Evasion):
    """
    In-memory Windows payload delivery template.

    Inherit from both ``Exploit`` and ``Evasion``.  The ``Exploit`` base
    provides the full driver pipeline (TCP handler, session, payload assembly).
    The ``Evasion`` mixin adds evasion-specific metadata and the optional
    ``cleanup()`` hook.

    Replace the body of ``run()`` with the actual bypass technique.
    """

    NAME = "Windows AV Bypass Template"
    DESCRIPTION = (
        "Template evasion module for in-memory payload delivery on Windows. "
        "Does not write to disk.  Replace run() with the real bypass technique."
    )
    AUTHOR = "4steroth"
    LICENSE = "BSD-3-CLAUSE"
    VERSION = "1.0"
    RANK = "normal"
    REFERENCES = []

    ARCH = [ARCH_X86, ARCH_X64]
    PLATFORM = [PLATFORM_WINDOWS]
    TARGET = [(0, "Windows x86/x64 - automatic")]

    # Evasion mixin attributes
    EVASION_TECHNIQUE = "in-memory payload execution"
    NEEDS_CLEANUP = False
    DEFAULT_OPTIONS = {
        # Pre-set EXITFUNC to thread so the host process stays alive
        # after the payload runs - typical for injected payloads.
        "EXITFUNC": "thread",
    }

    PAYLOAD_SPACE = 4096

    def run(self, ctx):
        """
        Deliver the payload using an in-memory technique.

        Replace this stub with the real bypass implementation.
        """
        raise NotImplementedError("This is a template - implement run() before using this module.")

    def cleanup(self, ctx):
        """
        No artefacts to clean up (NEEDS_CLEANUP = False).

        Override if the technique leaves threads, handles, or registry keys.
        """
