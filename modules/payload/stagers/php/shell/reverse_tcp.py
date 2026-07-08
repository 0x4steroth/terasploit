"""
Terasploit Framework (c) 2026

Author:          4steroth
License:         BSD-3-Clause
Path:            modules/payload/stagers/php/reverse_tcp.py
"""

from teralibs.tsf.base.payload import ARCH_PHP, PLATFORM_PHP, STAGER, PayloadHandler
from teralibs.tsf.core.payload.php.reverse_tcp import PHPReverseTCP


class TerasploitModule(PHPReverseTCP):
    """PHP Reverse TCP Stager."""

    NAME = "PHP Reverse TCP Stager"
    DESCRIPTION = "Reverse PHP connect back stager. Built to use shell stage."
    AUTHOR = ["egypt", "4steroth"]
    LICENSE = "BSD-3-CLAUSE"
    VERSION = "1.0"
    RANK = "normal"

    REFERENCES = [
        "https://github.com/rapid7/metasploit-framework/blob/master/"
        "modules/payloads/stagers/php/reverse_tcp.rb"
    ]

    PAYLOAD_TYPE = STAGER
    HANDLER = PayloadHandler.ReverseTCP

    STAGE_PATH = "php.shell"
    CACHED_SIZE = 1116

    ARCH = [ARCH_PHP]
    PLATFORM = [PLATFORM_PHP]
