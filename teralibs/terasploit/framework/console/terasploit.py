"""
Terasploit Framework (c) 2026

Author:          4steroth
License:         BSD-3-Clause
Path:            teralibs/terasploit/framework/console/terasploit.py
"""

import os
import readline

import teralibs.terasploit.framework.exploit.driver as _drv
from teralibs.terasploit.dependencies import DependencyChecker, DependencyReport
from teralibs.terasploit.framework.console.state import DATASTORE, FRAMEWORK_CORE_OPTIONS
from teralibs.terasploit.framework.modules.module_storage import ModuleStorage
from teralibs.terasploit.framework.services.banner import display_banner
from teralibs.terasploit.framework.services.printf import error, set_verbose, warning
from teralibs.terasploit.framework.thread.handler import ThreadHandler
from teralibs.tsf.utils.path import ModuleIndex


class Terasploit:
    """
    Core console base.

    Subclasses inherit all shared state through instance attributes so
    every command handler can reach the module index, datastore, and
    thread pool without any global variables.
    """

    _DEPENDENCY_FILES = ("reqs.txt", "reqs-extra.txt")
    _HISTORY_FILENAME = ".terasploit"

    def __init__(self, verbose=False, history_length=100):
        # Controls the REPL loop in the CLi subclass.
        self.console_toggle = True

        # Shared state available to all command handlers via self.*.
        self.modules = ModuleIndex()
        self.module_storage = ModuleStorage()
        self.datastore = DATASTORE
        self.thread_handler = ThreadHandler(max_threads=10)

        self.history_file = os.path.join(
            os.path.expanduser("~"),
            self._HISTORY_FILENAME,
        )
        self.history_length = history_length

        # Startup sequence - order matters.
        set_verbose(verbose)
        self._register_framework_options(verbose)
        # Apply MAX_THREADS from the framework datastore so operators who
        # persist the option with setg see it honoured on the next launch.
        self._apply_startup_framework_options()
        display_banner(self.modules.list())
        self.check_dependencies()
        self._load_history()

    def _register_framework_options(self, verbose):
        """
        Populate the framework scope in the datastore with FRAMEWORK_CORE_OPTIONS.

        Called once during __init__ before any module is loaded.  After
        registration, the verbose flag passed on the command line is
        written back so the stored VERBOSE value reflects the live state.
        """
        self.datastore.register("framework", FRAMEWORK_CORE_OPTIONS)

        if verbose:
            self.datastore.set("VERBOSE", "true", scope="framework")

    def _apply_startup_framework_options(self):
        """
        Apply framework options that have side effects beyond simple storage.

        Called once after _register_framework_options so that options with
        stored non-default values (e.g. set by a previous setg) take effect
        immediately on startup without requiring the user to re-set them.

        Currently handled:
          MAX_THREADS  - resizes the thread pool to the stored value.
          LISTENER_TIMEOUT - updates the module-level constant in driver.
        """
        raw_threads = self.datastore.get("MAX_THREADS", scope="framework")
        if raw_threads:
            try:
                n = int(raw_threads)
                if n >= 1:
                    self.thread_handler.set_max_threads(n)
            except (ValueError, TypeError):
                pass

        raw_timeout = self.datastore.get("LISTENER_TIMEOUT", scope="framework")
        if raw_timeout:
            try:
                _drv.LISTENER_ACCEPT_TIMEOUT = float(raw_timeout)
            except (ValueError, TypeError):
                pass

    def check_dependencies(self):
        """
        Validate every listed requirements file and shut down on failure.

        Running with unsatisfied dependencies would produce confusing
        ImportError tracebacks deep inside module code, so it is better
        to catch the problem early and give the user a clear message.
        """
        checker = DependencyChecker()
        combined = []

        # Use __file__ to locate the project root reliably regardless of how
        # the framework was launched (symlink, python -m, direct script, etc.).
        # terasploit.py lives at teralibs/terasploit/framework/console/terasploit.py
        # _here resolves to the containing directory (console/), so four more
        # dirname() calls are needed to climb out of console/ → framework/ →
        # terasploit/ → teralibs/ → project root.
        _here = os.path.dirname(os.path.abspath(__file__))
        req_dir = os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(_here)))),
            "data",
            "requirements",
        )

        for filename in self._DEPENDENCY_FILES:
            path = os.path.join(req_dir, filename)
            if not os.path.isfile(path):
                continue

            report = checker.check_file(path)
            combined.extend(report.results)

        final_report = DependencyReport(results=combined)
        if not final_report.is_clean():
            final_report.print_report()
            error("Dependency error - shutting down.")
            self.shutdown()

    def _load_history(self):
        """
        Restore the command history file from disk.

        Silently ignored when the file does not exist yet, which is
        the normal condition on a fresh installation.
        """
        if os.path.exists(self.history_file):
            try:
                readline.read_history_file(self.history_file)
            except OSError:
                warning(f"Requirement file does not exist: {self.history_file}")

    def _save_history(self):
        """
        Write the current readline history back to disk.

        The stored entry count is capped at the HISTORY_LENGTH framework
        option value so the file does not grow without bound over many
        sessions.
        """
        length = self.datastore.get("HISTORY_LENGTH", scope="framework")
        try:
            cap = int(length) if length else self.history_length
        except (ValueError, TypeError):
            cap = self.history_length

        readline.set_history_length(cap)
        try:
            readline.write_history_file(self.history_file)
        except OSError:
            pass

    def shutdown(self):
        """
        Cleanly terminate the console session.

        Steps performed in order:
        Save readline history to disk; Stop the background thread pool;
        Unload all active modules, triggering their stop() hooks;
        Clear the run flag so the REPL loop exits on the next iteration.
        """
        self._save_history()
        self.thread_handler.shutdown(timeout=3.0)
        self.module_storage.clear_all()
        self.console_toggle = False
