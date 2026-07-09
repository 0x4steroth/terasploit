"""
Terasploit Framework (c) 2026

Author:          4steroth
License:         BSD-3-Clause
Path:            teralibs/terasploit/framework/console/tsf.py
"""

import argparse
import os
import sys

from teralibs.terasploit.framework.services.printf import (
    error,
    info,
    print_line,
    set_verbose,
)
from teralibs.terasploit.metadata import VERSION


# Argument parser
class CompactHelpFormatter(argparse.RawDescriptionHelpFormatter):
    """
    RawDescriptionHelpFormatter with a tighter help-column alignment.

    argparse's default max_help_position is 24, which pushes help text
    far to the right (or onto a new line) for long option strings like
    --resource FILE.  Capping it at 36 keeps descriptions on the
    same line without sacrificing readability.
    """

    def __init__(self, *args, **kwargs):
        kwargs.setdefault("max_help_position", 40)
        kwargs.setdefault("width", 100)
        super().__init__(*args, **kwargs)


def _build_parser():
    parser = argparse.ArgumentParser(
        prog="teraconsole",
        formatter_class=CompactHelpFormatter,
    )

    parser.add_argument(
        "-d",
        "--debug",
        action="store_true",
        help="Enable verbose/debug output (shows [~] messages)",
    )
    parser.add_argument(
        "-v",
        "--version",
        action="store_true",
        help="Print version and exit",
    )
    parser.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="Skip the banner",
    )
    parser.add_argument(
        "-r",
        "--resource",
        metavar="FILE",
        help="Execute commands from a resource (.rc) script file",
    )
    parser.add_argument(
        "-m",
        "--module",
        metavar="MODULE",
        help="Preload a module before dropping into the REPL",
    )
    parser.add_argument(
        "-x",
        "--execute",
        metavar="CMDs",
        help='Execute semicolon-separated commands, then drop to REPL (e.g. "use x; set Y z")',
    )

    return parser


# Resource script runner
def _run_resource(console, filepath):
    """
    Execute each non-blank, non-comment line of *filepath* as a console command.
    """
    if not os.path.isfile(filepath):
        error(f"Resource file not found: {filepath!r}")
        return

    info(f"Running resource script: {filepath}")
    with open(filepath, encoding="utf-8") as fh:
        for lineno, raw in enumerate(fh, start=1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            try:
                cmd, args = console.parse_line(line)
                if cmd:
                    console.dispatch(cmd, args)
            except RuntimeError as exc:
                error(f"[rc:{lineno}] {exc}")


# Inline command string runner
def _run_inline(console, command_string):
    """Execute a semicolon-separated list of commands immediately."""
    for raw in command_string.split(";"):
        line = raw.strip()
        if not line:
            continue
        try:
            cmd, args = console.parse_line(line)
            if cmd:
                console.dispatch(cmd, args)
        except RuntimeError as exc:
            error(f"[inline] {exc}")


# Entry point
def main():
    """The main entry point of terasploit framework"""
    try:
        parser = _build_parser()
        opts = parser.parse_args()

        # --version - print and exit immediately, no console init needed.
        if opts.version:
            print_line(f"Terasploit Framework {VERSION}")
            sys.exit(0)

        # Apply debug flag first so banner / dep-check log at the right level.
        if opts.debug:
            set_verbose(True)

        # --quiet: patch banner + dep-report BEFORE importing CLi (its __init__
        # triggers both).  Importing the modules here loads them into sys.modules
        # so the lambda replacements take effect before CLi.__init__ runs.
        if opts.quiet:
            import teralibs.terasploit.dependencies as _dep_mod
            import teralibs.terasploit.framework.services.banner as _banner_mod

            _banner_mod.display_banner = lambda _: None
            _dep_mod.DependencyReport.print_report = lambda self: None

        # Import CLi after quiet patches are applied.
        from teralibs.terasploit.framework.console.cli import CLi

        # Initialise the console - runs banner + dep check internally.
        console = CLi(verbose=opts.debug)

        # --module: preload a module before handing control to the user.
        if opts.module:
            console.dispatch("use", [opts.module])

        # --execute: run inline commands.
        if opts.execute:
            _run_inline(console, opts.execute)

        # --resource: run a script file.
        if opts.resource:
            _run_resource(console, opts.resource)

        # Drop into the interactive REPL.
        console.start()

    except KeyboardInterrupt:
        print_line("\n[!] Keyboard interrupt received, exiting...")
        sys.exit(0)

    except Exception as exc:
        error(f"Unexpected error: {exc}")
        sys.exit(1)
