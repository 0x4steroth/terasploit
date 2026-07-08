"""
Terasploit Framework (c) 2026

Author:          4steroth
License:         BSD-3-Clause
Path:            teralibs/tsf/pex/proto/http/fingerprint.py
"""

import re
from dataclasses import dataclass, field


@dataclass
class FingerprintOptions:
    """
    Caller-supplied fingerprint validation config.
    Mirrors MSF's HttpFingerprint class constant pattern.

    Attributes:
        patterns: Compiled regexes — ALL must match the signature.
        uri:      URI to request for fingerprinting.
        method:   HTTP method to use.
    """

    patterns: list[re.Pattern[str]]
    uri: str = "/"
    method: str = "GET"


class FingerprintError(Exception):
    """Base class for fingerprint validation failures."""


class FingerprintMismatch(FingerprintError):
    """Signature did not match a required pattern."""


class FingerprintUnreachable(FingerprintError):
    """Target did not respond to the fingerprinting request."""


@dataclass
class HttpFingerprint:
    """
    Structured fingerprint extracted from an HTTP response.
    Mirrors the fprint hash built by MSF's http_fingerprint().

    Header keys are normalized:
        'Set-Cookie'       -> 'header_set_cookie'
        'WWW-Authenticate' -> 'header_www_authenticate'
    """

    uri: str
    method: str
    server_port: int
    code: str
    message: str
    signature: str
    content: str
    headers: dict[str, str] = field(default_factory=dict)
