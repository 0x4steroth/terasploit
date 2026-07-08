"""
Terasploit Framework (c) 2026

Author:          4steroth
License:         BSD-3-Clause
Path:            teralibs/terasploit/framework/services/printf.py
"""

import dataclasses
import datetime
import sys


# ANSI escape codes
RESET = "\033[0m"
BOLD = "\033[1m"
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
BLUE = "\033[34m"
CYAN = "\033[36m"
GRAY = "\033[90m"
WHITE = "\033[37m"


@dataclasses.dataclass
class State:
    """Holds the state of the console print function."""

    # When True, debug() calls produce output; otherwise they are no-ops.
    VERBOSITY = False

    # When True, every log line is prefixed with the current wall-clock time.
    TIMESTAMP = False


# State mutators


def set_verbose(enabled=True):
    """
    Toggle debug output on or off.
    """
    State.VERBOSITY = enabled


def get_verbose():
    """
    Return True when debug output is currently enabled.
    """
    return State.VERBOSITY


def set_timestamp(enabled=True):
    """
    Toggle wall-clock timestamp prefixes on log lines.
    """

    State.TIMESTAMP = enabled


# Internal emission helpers


def _emit_write(message):
    """
    Write one formatted log line to stdout and flush immediately.

    Using sys.stdout.write instead of print_line() avoids any implicit
    buffering and gives precise control over line endings.
    """
    sys.stdout.write(message)
    sys.stdout.flush()


def _emit(symbol, color, message):
    """
    Format and write one log line with the given *symbol* and *color*.
    """
    if State.TIMESTAMP is True:
        now = datetime.datetime.now().strftime("%H:%M:%S")
        timestamp = f"[{CYAN}{now}{RESET}]"
        _emit_write(f"{timestamp} [{color}{symbol}{RESET}] {message}\n")

    if State.TIMESTAMP is False:
        _emit_write(f"{color}{symbol}{RESET} {message}\n")


# Public log functions


def info(message):
    """
    Emit a [*] informational message (blue).
    """
    _emit("[*]" if not State.TIMESTAMP else "INFO", BOLD + BLUE, message)


def success(message):
    """
    Emit a [+] success message (green).
    """
    _emit("[+]" if not State.TIMESTAMP else "SUCCESS", BOLD + GREEN, message)


def warning(message):
    """
    Emit a [!] warning message (yellow).
    """
    _emit("[!]" if not State.TIMESTAMP else "WARNING", BOLD + YELLOW, message)


def error(message):
    """
    Emit a [-] error message (red).
    """
    _emit("[-]" if not State.TIMESTAMP else "ERROR", BOLD + RED, message)


def debug(message):
    """
    Emit a [~] debug message (gray).

    The call is a no-op when verbose mode is disabled, so callers do not
    need to guard each invocation themselves.
    """
    if State.VERBOSITY:
        _emit("[~]" if not State.TIMESTAMP else "DEBUG", CYAN, message)


def print_line(
    *args,
    sep=" ",
    end="\n",
    file=sys.stdout,
    flush=False,
):
    """
    Write a plain line to stdout with no symbol prefix.
    Used for table output, banners, and any prose that should not carry
    a log-level symbol.
    """
    file.write(
        (sep if sep is not None else " ").join(str(a) for a in args)
        + (end if end is not None else "\n")
    )
    if flush:
        file.flush()
