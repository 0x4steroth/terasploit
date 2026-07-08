"""
Terasploit Framework (c) 2026

Author:          4steroth
License:         BSD-3-Clause
Path:            modules/payload/stagers/python/reverse_tcp.py
"""

from teralibs.tsf.base.payload import ARCH_PYTHON, PLATFORM_PYTHON, STAGER, PayloadHandler
from teralibs.tsf.core.payload.python.reverse_tcp import PythonReverseTCP


class TerasploitModule(PythonReverseTCP):
    """Python Reverse TCP Stager."""

    NAME = "Python Reverse TCP Stager"
    DESCRIPTION = "Reverse Python connect back stager. Built to use shell stage."
    AUTHOR = ["4steroth"]
    LICENSE = "BSD-3-CLAUSE"
    VERSION = "1.0"
    RANK = "normal"
    REFERENCES = []

    PAYLOAD_TYPE = STAGER
    HANDLER = PayloadHandler.ReverseTCP

    STAGE_PATH = "python.shell"
    CACHED_SIZE = 1116

    ARCH = [ARCH_PYTHON]
    PLATFORM = [PLATFORM_PYTHON]
