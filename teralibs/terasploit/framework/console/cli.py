"""
Terasploit Framework (c) 2026

Author:          4steroth
License:         BSD-3-Clause
Path:            teralibs/terasploit/framework/console/cli.py
"""

import os
import shlex
import subprocess
import time

from teralibs.terasploit.framework.console.helpers import _to_path
from teralibs.terasploit.framework.console.loaders import ConsoleLoader
from teralibs.terasploit.framework.console.show import ConsoleRenderer
from teralibs.terasploit.framework.console.terasploit import Terasploit
from teralibs.terasploit.framework.exploit.driver import (
    DriverDeps,
    ExploitDriver,
    all_sessions,
    get_session,
    remove_session,
)
from teralibs.terasploit.framework.exploit.entry import open_shell
from teralibs.terasploit.framework.services import tables as tbl
from teralibs.terasploit.framework.services.banner import display_banner
from teralibs.terasploit.framework.services.printf import (
    BOLD,
    CYAN,
    GREEN,
    RED,
    RESET,
    WHITE,
    YELLOW,
    debug,
    error,
    info,
    print_line,
    success,
    warning,
)
from teralibs.tsf.core.module.context import (
    AuxiliaryContext,
    AuxiliaryContextDeps,
    ExploitContext,
    ExploitContextDeps,
    PostContext,
    PostContextDeps,
)


# Command alias sets
_EXIT_ALIASES = frozenset({"exit", "quit", "q", "close", "terminate"})
_RUN_ALIASES = frozenset({"run", "exploit", "execute"})


class CLi(ConsoleLoader, ConsoleRenderer, Terasploit):
    """
    Interactive Terasploit console.

    Inherits all shared state and lifecycle management from Terasploit,
    display helpers from Show, loader helpers from LoaderMixin, and
    adds the read-eval loop, line parser, command dispatcher, and every
    remaining command handler method.
    """

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

        # Give the tables module access to the module index so it can
        # load metadata while rendering the modules table.
        tbl.set_module_index(self.modules)

    # REPL helpers

    def _user_prompt(self):
        """
        Build the context-sensitive prompt string.

        The prompt label and trailing character are read from the framework
        options PROMPT and PROMPT_CHAR so the user can customise them with
        setg without restarting the console.
        """
        label = self.datastore.get("PROMPT", scope="framework")
        char = self.datastore.get("PROMPT_CHAR", scope="framework")

        entry = self.module_storage.module()

        if entry is None:
            return f"\001\033[4m\002{label}\001{RESET}\002 {char} "

        display = _to_path(entry.name)
        return (
            f"\001\033[4m\002{label}\001{RESET}\002 "
            f"(\001{BOLD}\002\001{RED}\002{display}\001{RESET}\002) {char} "
        )

    def parse_line(self, line):
        """
        Tokenise a line using POSIX shell quoting rules.

        Returns a (command, args) pair where command is the first token
        lowercased and args is the remaining token list.

        Raises RuntimeError when shlex finds an unmatched quote or other
        shell syntax error so the REPL can print it cleanly.
        """
        stripped = line.strip()

        if not stripped:
            return "", []

        try:
            tokens = shlex.split(stripped)
        except ValueError as exc:
            raise RuntimeError(f"Parse error: {exc}") from exc

        return tokens[0].lower(), tokens[1:]

    def dispatch(self, command, args):
        """
        Route a command to its _cmd_* handler method.

        Exit and run alias sets are resolved first so they work regardless
        of whether a dedicated method exists for every alias string.
        """
        if command in _EXIT_ALIASES:
            self.shutdown()
            return

        if command in _RUN_ALIASES:
            command = "run"

        if command == "?":
            command = "help"

        if command in ("session",):
            command = "sessions"

        if command in ("i",):
            command = "interact"

        if command in ("k",):
            command = "kill"

        handler = getattr(self, f"_cmd_{command}", None)
        if handler:
            debug(f"dispatch -> {command} {args}")
            handler(args)
            return

        warning(f"Unknown command: '{command}'.  Type 'help' for a list.")

    # Top-level command handlers

    def _cmd_banner(self, _):
        """Display the terasploit framework banner."""
        display_banner(self.modules.list())

    def _cmd_help(self, _):
        """Display a grouped command reference table."""
        sections = [
            (
                "Core",
                [
                    ("help / ?", "Show this help menu"),
                    ("banner", "Display the terasploit framework banner"),
                    ("exit / quit", "Exit the console"),
                    ("clear", "Clear the terminal screen"),
                    ("exec <command>", "Execute a system shell command"),
                ],
            ),
            (
                "Module",
                [
                    ("use <module>", "Load a module by name or path"),
                    ("back", "Unload the current module"),
                    ("info [module]", "Show module metadata"),
                    ("search <query>", "Search available modules"),
                    ("reload", "Rescan module index and reset encoder cache"),
                    ("show all", "List all available modules"),
                    ("show options", "Basic options and targets for the active module"),
                    (
                        "show advanced",
                        "Advanced options for the active module and payload",
                    ),
                    (
                        "show evasion",
                        "Evasion options for the active module and payload",
                    ),
                    ("show targets", "Targets for the active module"),
                    ("show payloads", "List payload modules"),
                    ("show exploits", "List exploit modules"),
                    ("show auxiliary", "List auxiliary modules"),
                    ("show encoders", "List encoder modules"),
                ],
            ),
            (
                "Options",
                [
                    ("set <name> <value>", "Set a module/framework option"),
                    ("set PAYLOAD <path>", "Load and validate a payload"),
                    ("set TARGET <id>", "Select a target by numeric ID"),
                    ("unset <name>", "Reset a module option to empty"),
                    ("setg <name> <value>", "Set a persistent global framework option"),
                    ("unsetg <name>", "Reset a global framework option to empty"),
                ],
            ),
            (
                "Execution",
                [
                    (
                        "run / exploit",
                        "Execute module - blocks until done, Ctrl-C to kill",
                    ),
                    ("check", "Test target vulnerability without exploiting"),
                    ("jobs", "List all jobs and their status"),
                    ("jobs clear", "Remove completed / failed / killed jobs"),
                ],
            ),
            (
                "Sessions",
                [
                    ("sessions", "List all open sessions"),
                    (
                        "sessions -C <id> <cmd>",
                        "Run a single command on a session inline",
                    ),
                    ("interact <id>", "Attach to an open session"),
                    (
                        "interact <id> <plat>",
                        "Attach with platform hint (unix/windows)",
                    ),
                    ("kill <session_id>", "Close a TCP session gracefully"),
                    ("kill <job_id>", "Stop a running job and shut its listener down"),
                    ("kill all", "Close every open session"),
                ],
            ),
            (
                "Nop",
                [
                    (
                        "generate [size] [-b <bc>]",
                        "Generate a NOP sled from the active nop module",
                    ),
                ],
            ),
        ]
        print_line()
        for section_name, entries in sections:
            print_line(f"{BOLD + WHITE}{section_name} commands{RESET}\n")
            print_line(f"   {'Command':<30}  Description")
            print_line(f"   {'-' * 7:<30}  {'-' * 11}")

            for cmd, desc in entries:
                print_line(f"   {cmd:<30}  {desc}")
            print_line("\n")

    def _cmd_clear(self, _):
        """Clear the terminal screen using the appropriate platform command."""
        if os.name == "nt":
            os.system("cls")
        else:
            os.system("clear")

    def _cmd_exec(self, args):
        """
        Execute a system shell command and stream its output to the console.

        The command is deliberately run through the system shell (sh -c on
        Unix, cmd.exe on Windows) so shell features such as pipes,
        redirection, and environment variable expansion work as expected.

        Security NOTE: shell=True is intentional here.  The framework
        console is an operator-facing tool; running arbitrary local shell
        commands is a first-class feature, not a misconfiguration.
        """
        if not args:
            warning("Usage: exec <command>  (example: exec whoami)")
            return

        command_string = " ".join(args)

        info(f"Executing: {command_string}")
        print_line()

        try:
            # shell=True is intentional - see docstring above.
            process = subprocess.run(
                command_string,
                shell=True,
                check=False,
            )
            print_line()
            if process.returncode != 0:
                warning(f"Command exited with status {process.returncode}.")

        except Exception as exc:  # pylint: disable=broad-except
            error(f"Shell execution failed: {exc}")

    def _cmd_reload(self, _):
        """
        Force-rescan the module index and reset the encoder registry.

        Picks up any new modules added to the modules/ directory since the
        framework started and clears the EncoderFactory auto-discovery cache
        so new encoders are re-discovered on next use.
        """
        from teralibs.terasploit.framework.encoder.factory import EncoderFactory

        self.modules.refresh(force=True)
        EncoderFactory.reset()
        count = len(self.modules)
        success(f"Module index refreshed - {count} module(s) indexed.")

    def _cmd_search(self, args):
        """
        Search the module index and display results in a table.

        When the query contains multiple words all words must appear in
        the module name (AND logic).  Single-word queries use plain
        substring matching.
        """
        if not args:
            warning("Usage: search <query> [more words...]")
            return

        query = " ".join(args)
        fuzzy = len(args) > 1
        results = self.modules.search(query, fuzzy=fuzzy)

        if not results:
            warning(f"No modules matching '{query}'.")
            return

        print_line(f'\nSearch: "{query}"\n')
        tbl.modules_table(results)

        # Guide for users.
        print_line(
            "\n\nInteract with a module by path using",
            f"the command '{GREEN}use <module_path>{RESET}'\n",
        )

    def _cmd_info(self, args):
        """
        Display metadata for the active module or a named one.

        When args is non-empty the named module is loaded just for
        inspection without changing the active module slot.
        """
        if args:
            name = args[0].replace("/", ".")
            mod = self.modules.load(name)

            if mod is None:
                error(f"Module not found: {args[0]!r}")
                return

            obj = getattr(mod, "TerasploitModule", None)

            if obj is None:
                error(f"Module {args[0]!r} has no TerasploitModule class.")
                return

        else:
            entry = self.module_storage.module()

            if entry is None:
                warning("No module loaded.  Run 'info <module>' or load one first.")
                return

            obj = type(entry.module)
            name = entry.name

        print_line()

        meta_fields = [
            ("Name", "NAME"),
            ("Module", None),
            ("Platform", "PLATFORM"),
            ("Arch", "ARCH"),
            ("Rank", "RANK"),
            ("Description", "DESCRIPTION"),
            ("Author", "AUTHOR"),
            ("License", "LICENSE"),
            ("References", "REFERENCES"),
        ]

        for label, attribute in meta_fields:
            if attribute is None:
                print_line(f"   {BOLD}{label}:{RESET} {_to_path(name)}")
                continue

            value = getattr(obj, attribute, None)

            if value is None:
                continue

            if isinstance(value, (list, tuple)) and value:
                print_line(f"   {BOLD}{label}:{RESET}")
                for item in value:  # pylint: disable=not-an-iterable
                    print_line(f"      {item}")

            elif value:
                # Scalar values (str, int, Enum, etc.) - render on one line.
                print_line(f"   {BOLD}{label}:{RESET} {value}")

        print_line()

    # Execution

    def _cmd_generate(self, args):
        """
        Generate a NOP sled from the active NOP module.

        When no size is given, NopSledSize from the datastore is used.
        Badchars use the same hex format as BADCHARS (e.g. ``\\x00\\x0a``).
        Output is a hex dump with a printable-character column.
        """
        entry = self.module_storage.module()
        if entry is None:
            warning("No module loaded.  Use 'use <module>' first.")
            return

        if not entry.name.startswith("nop"):
            warning(f"'{_to_path(entry.name)}' is not a NOP module.  Load a nop/* module first.")
            return

        # --- Parse arguments ---
        sled_size = 0
        badchars: frozenset[int] = frozenset()

        i = 0
        while i < len(args):
            token = args[i]
            if token == "-b" and i + 1 < len(args):
                i += 1
                try:
                    from teralibs.terasploit.framework.payload.badchars import BadCharFilter

                    badchars = BadCharFilter.parse(args[i])
                except ValueError as exc:
                    error(f"Invalid badchars: {exc}")
                    return
            else:
                try:
                    sled_size = int(token)
                except ValueError:
                    error(f"Invalid size argument: {token!r}  (expected an integer)")
                    return
            i += 1

        # Fall back to datastore NopSledSize when no size was passed.
        if sled_size <= 0:
            raw = self.datastore.get("NopSledSize") or "0"
            try:
                sled_size = int(raw)
            except (TypeError, ValueError):
                sled_size = 0

        if sled_size <= 0:
            error("No size specified.  Pass a size argument or set NopSledSize.")
            return

        self._generate_nops_sled(entry, sled_size, badchars)

    def _generate_nops_sled(self, entry, sled_size, badchars):
        """Generate no-operation sled."""

        # Fall back to datastore BADCHARS when -b was not passed.
        if not badchars:
            raw_bc = self.datastore.get("BADCHARS") or ""
            if raw_bc:
                try:
                    from teralibs.terasploit.framework.payload.badchars import BadCharFilter

                    badchars = BadCharFilter.parse(raw_bc)
                except ValueError:
                    pass

        # --- Generate ---
        result = entry.module.generate(sled_size, badchars)

        if not result.success:
            error(f"[NopSled] Generation failed: {result.error}")
            return

        sled = result.sled_bytes
        info(
            f"NOP sled: {len(sled):,} bytes via '{result.nop_name}'"
            + (f" (avoiding {len(badchars)} bad byte(s))" if badchars else "")
        )

        # Hex dump output - 16 bytes per row with printable-char column.
        print_line()
        for offset in range(0, len(sled), 16):
            chunk = sled[offset : offset + 16]
            hex_part = " ".join(f"{b:02x}" for b in chunk)
            asc_part = "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in chunk)
            print_line(f"  {offset:04x}  {hex_part:<47}  {asc_part}")

        print_line()
        success(f"Generated {len(sled):,}-byte NOP sled.")

    def _cmd_check(self, _):
        """
        Probe the target for vulnerability without launching the full exploit.

        Calls the active module's ``check(ctx)`` method when one is defined.
        The method should return a string describing the result, or raise
        RuntimeError / NotImplementedError when checking is not supported.
        """
        entry = self.module_storage.module()
        if entry is None:
            warning("No module loaded.  Use 'use <module>' first.")
            return

        if not hasattr(entry.module, "check"):
            warning(
                f"{entry.name} does not implement a check() method. "
                "Run 'run' to execute the full exploit."
            )
            return

        is_exploit = entry.name.startswith("exploit")

        # Payload only relevant for exploit modules
        payload_entry = None
        payload_obj = None

        if is_exploit is True:
            # Since we can import payloads as well, we will get the payload entry
            # to module_storage.module() as well.
            payload_entry = self.module_storage.payload() or self.module_storage.module()

            # The payload object
            payload_obj = payload_entry.module if payload_entry is not None else None

        missing = (
            self.datastore.missing_required("module") + self.datastore.missing_required("payload")
            if is_exploit
            else self.datastore.missing_required("module")
        )
        if missing:
            error(f"Required option(s) not set: {RED}{', '.join(missing)}{RESET}.")
            return

        if is_exploit:

            def _run_exploit(worker_ctx):
                _ctx = ExploitContext(
                    ExploitContextDeps(
                        job_id=worker_ctx.job_id,
                        module_obj=entry.module,
                        payload_obj=payload_obj,
                        datastore=self.datastore,
                        bus=worker_ctx.bus,
                    )
                )
                entry.module.check(_ctx)

            driver = _run_exploit
        else:

            def _run_auxiliary(worker_ctx):
                _ctx = AuxiliaryContext(
                    AuxiliaryContextDeps(
                        job_id=worker_ctx.job_id,
                        bus=worker_ctx.bus,
                        datastore=self.datastore,
                    )
                )
                entry.module.run(_ctx)

            driver = _run_auxiliary

        try:
            task_id = self.thread_handler.submit(driver)

        except (ValueError, OSError) as exc:
            error(f"Driver error: {exc}")
            if isinstance(driver, ExploitDriver) and driver is not None:
                driver.stop()
            return

        self._async_job_runner(task_id)

    def _cmd_run(self, _):
        """
        Execute the active module and block until it finishes.

        The driver starts the TCP listener, runs the exploit module in a
        background thread, then this method streams all job output live to
        the console and only returns the prompt when the job reaches a
        terminal state (completed / failed / killed).
        """
        entry = self.module_storage.module()

        if entry is None:
            warning("No module loaded.  Use 'use <module>' first.")
            return

        is_nop = entry.name.startswith("nop")
        # Nop modules are not executed via run - they generate sleds.
        # Redirect the user to the generate command.
        if is_nop:
            warning(f"'{_to_path(entry.name)}' is a NOP module - use 'generate' to produce a sled.")
            return

        # Run post module
        is_post = entry.name.startswith("post")
        if is_post is True:
            self._run_post_module()
            return

        is_exploit = (
            entry.name.startswith("exploit")
            or entry.name.startswith("payload")
            or entry.name.startswith("evasion")
        )

        missing = (
            self.datastore.missing_required("module") + self.datastore.missing_required("payload")
            if is_exploit
            else self.datastore.missing_required("module")
        )
        if missing:
            error(f"Required option(s) not set: {RED}{', '.join(missing)}{RESET}.")
            return

        # Payload only relevant for exploit modules
        payload_entry = None
        payload_obj = None

        if is_exploit is True:
            # Since we can import payloads as well, we will get the payload entry
            # to module_storage.module() as well.
            payload_entry = self.module_storage.payload() or self.module_storage.module()

            # The payload object
            payload_obj = payload_entry.module if payload_entry is not None else None

        if not hasattr(entry.module, "run"):
            warning(f"Module '{_to_path(entry.name)}' has no 'run' method.")
            return

        # Execute the module
        self._run_module(entry, is_exploit, payload_obj)

    def _run_module(self, entry, is_exploit, payload_obj):
        """Execute auxiliary/exploit modules."""

        debug(f"Running module: {_to_path(entry.name)}")
        driver = None
        if is_exploit is True:
            driver = ExploitDriver(
                DriverDeps(
                    module_obj=entry.module,
                    payload_obj=payload_obj,
                    datastore=self.datastore,
                    thread_handler=self.thread_handler,
                    output_bus=self.thread_handler.output_bus,
                    session_callback=self._on_session_opened,
                )
            )
        else:

            def _run_auxiliary(worker_ctx):
                _ctx = AuxiliaryContext(
                    AuxiliaryContextDeps(
                        job_id=worker_ctx.job_id,
                        bus=worker_ctx.bus,
                        datastore=self.datastore,
                    )
                )
                entry.module.run(_ctx)

            driver = _run_auxiliary
        try:
            task_id = (
                driver.run()
                if isinstance(driver, ExploitDriver) and is_exploit and driver is not None
                else self.thread_handler.submit(driver)
            )

        except (ValueError, OSError) as exc:
            error(f"Driver error: {exc}")
            if isinstance(driver, ExploitDriver) and driver is not None:
                driver.stop()
            return

        self._async_job_runner(task_id)

    def _run_post_module(self):
        """
        Running post module gets a standalone method because it is
        different to auxiliary and exploit context.
        """
        session_id = self.datastore.get("SESSION")
        session = get_session(session_id) if session_id else None

        entry = self.module_storage.module()

        if session is None:
            error(f"Session {session_id!r} not found. Use 'sessions' to list open sessions.")
            return

        if not session.runtime.alive:
            error(f"Session {session_id!r} is no longer alive.")
            return

        # The thread worker injects a ModuleContext as the first positional
        # arg into every submitted callable.  We intercept it here and
        # exchange it for a PostContext that adds session access and option
        # lookup on top of the standard logging surface.

        def _run_post(worker_ctx):
            post_ctx = PostContext(
                PostContextDeps(
                    job_id=worker_ctx.job_id,
                    bus=worker_ctx.bus,
                    datastore=self.datastore,
                    session=session,
                )
            )
            entry.module.run(post_ctx)

        try:
            task_id = self.thread_handler.submit(_run_post)
        except (ValueError, OSError) as exc:
            error(f"Post module error: {exc}")
            return

        self._async_job_runner(task_id)

    def _async_job_runner(self, task_id):
        """Acts as the "Standard Output (Stdout) Proxy"""
        try:
            while not self.thread_handler.wait_until_done(task_id, poll=0.15):
                if self.thread_handler.output_bus.pending() > 0:
                    self._flush_job_output()

        except KeyboardInterrupt:
            print_line()
            warning("Interrupt - killing job.")
            self.thread_handler.kill_task(task_id)
            # A second Ctrl+C while draining (slow module teardown, blocked
            # socket, long scan loop) must not propagate — the job is already
            # being killed and there is nothing further to do.  Absorb it so
            # control returns cleanly to the REPL prompt.
            while not self.thread_handler.wait_until_done(task_id, poll=0.15):
                try:
                    if self.thread_handler.output_bus.pending() > 0:
                        self._flush_job_output()

                # We ignore any ctrl+c coming. You executed it, finish it.
                except KeyboardInterrupt:
                    continue

        # Final drain so the last events (session opened, errors) are visible.
        self._flush_job_output()

    def _on_session_opened(self, session):
        """Called by the ExploitDriver when a new session is established."""

        session_id = session.session_id
        addr = session.transport.addr

        self.thread_handler.output_bus.emit(
            "session", "success", f"Session {session_id} opened ({addr[0]}:{addr[1]})"
        )

    # Session management

    def _cmd_sessions(self, args):
        """
        List all currently open Shell Sessions.
        """
        # Handle sessions -C <id> <command>
        if args and args[0] == "-C":
            if len(args) < 3:
                warning("Usage: sessions -C <session_id> <command>")
                return
            sid = args[1]
            cmd_str = " ".join(args[2:])
            session = all_sessions().get(sid)
            if session is None:
                error(f"No session with ID '{sid}'.")
                return
            if not session.runtime.alive:
                error(f"Session {sid} is dead.")
                return
            try:
                session.send_command(cmd_str)
                output = session.read_output(timeout=10.0)
                print_line(output.rstrip() if output else "(no output)")
            except (OSError, AttributeError) as exc:
                error(f"Session command failed: {exc}")
            return

        sessions = all_sessions()
        print_line()

        if not sessions:
            info("No open sessions.")
            print_line()
            return

        w_id = max(len("Id"), max(len(s.session_id) for s in sessions.values()))
        w_host = max(len("Target"), max(len(s.transport.addr[0]) for s in sessions.values()))
        w_platform = max(len("Platform"), max(len(s.platform) for s in sessions.values()))

        # Header
        print_line("Sessions")
        print_line("========\n")

        # Table header
        print_line(f"   {'Id':<{w_id}}  {'Target':<{w_host}}  {'Platform':<{w_platform}}  Opened")
        print_line(f"   {'-' * 2:<{w_id}}  {'-' * 6:<{w_host}}  {'-' * 8:<{w_platform}}  {'-' * 6}")

        now = time.time()
        for sid, sess in sessions.items():
            age = int(now - sess.runtime.opened_at)
            status = f"{GREEN}alive{RESET}" if sess.runtime.alive else f"{RED}dead{RESET}"
            print_line(
                f"   {sid:<{w_id}}  "
                f"{sess.transport.addr[0]:<{w_host}}  "
                f"{sess.platform:<{w_platform}}  "
                f"{status} {age}s ago"
            )

        print_line(
            "\n\nUse 'interact <id>' to attach, or "
            "'sessions -C <id> <cmd>' to run a single command."
        )
        print_line()

    def _cmd_kill(self, args):
        """
        Gracefully close a session or stop a running job.

        The command auto-detects whether the target ID belongs to a session
        (TCP connection) or a job (exploit handler).
        """
        if not args:
            warning("Usage: kill <session_id | job_id> | kill all")
            return

        target = args[0].lower()

        if target == "all":
            sessions = all_sessions()
            if not sessions:
                info("No open sessions to kill.")
                return
            for sid, sess in list(sessions.items()):
                self._kill_session(sid, sess, remove_session)
            success("All sessions closed.")
            return

        sessions = all_sessions()
        if target in sessions:
            self._kill_session(target, sessions[target], remove_session)
            return

        killed = self.thread_handler.kill_task(target)
        if killed:
            success(f"Job {target[:8]} signalled to stop - listener shut down.")
            return

        error(
            f"No session or job matching {target!r}.  Use 'sessions' or 'jobs' to list active IDs."
        )

    @staticmethod
    def _kill_session(session_id, session, remove_fn):
        """Close a session socket gracefully and remove it from the registry."""
        try:
            session.close()

        except Exception:
            pass
        remove_fn(session_id)

        addr = session.transport.addr
        success(f"Session {session_id} ({addr[0]}:{addr[1]}) closed.")

    def _cmd_interact(self, args):
        """
        Attach to an open session and launch the Quasarix shell.

        The shell type is selected automatically based on the session's
        stored platform attribute.  An explicit platform can be supplied
        as a second argument to override the stored value.
        """
        if not args:
            warning("Usage: interact <session_id> [platform]")
            self._cmd_sessions([])
            return

        session_id = args[0]
        platform = args[1] if len(args) > 1 else None

        session = get_session(session_id)

        if session is None:
            error(f"No session with ID {session_id!r}.")
            info("Use 'sessions' to list open sessions.")
            return

        if not session.runtime.alive:
            error(f"Session {session_id} is no longer alive.")
            return

        effective_platform = platform or session.platform or "generic"
        effective_handler = getattr(session.transport, "handler", "reverse_tcp") or "reverse_tcp"

        info(
            f"Starting {effective_platform}/{effective_handler} shell on session "
            f"{session_id} ({session.transport.addr[0]}:{session.transport.addr[1]})..."
        )

        open_shell(
            session=session,
            platform=effective_platform,
            session_registry_fn=all_sessions,
        )

    # Jobs

    def _cmd_jobs(self, args):
        """Display background jobs or clear completed ones."""
        if args and args[0].lower() == "clear":
            removed = self.thread_handler.clear_completed()
            success(f"Cleared {removed} completed job(s).")
            return

        tasks = self.thread_handler.all_tasks()

        print_line()
        if not tasks:
            info("No jobs.")
            print_line()
            return

        status_colors = {
            "queued": YELLOW,
            "running": CYAN,
            "completed": GREEN,
            "failed": RED,
            "killed": RED,
        }

        # Header
        print_line("Jobs")
        print_line("====\n")

        # Table header
        print_line(f"   {'Id':<8}  Status")
        print_line(f"   {'-' * 2:<8}  {'-' * 6}")

        for task_id, task_info in tasks.items():
            status = task_info["status"]
            color = status_colors.get(status, RESET)
            short_id = task_id[:8]
            print_line(f"   {short_id:<8}  {color}{status}{RESET}")

        print_line("\n")

    # REPL entry point

    def start(self):
        """
        Enter the interactive read-eval loop.

        Runs until console_toggle is set to False by the shutdown() method.
        Background job output is flushed before each prompt so users see
        results as soon as they are available.

        Keyboard interrupt (Ctrl-C) prints a warning and restarts the
        prompt without exiting, matching the behaviour expected from an
        interactive security console.

        End-of-file (Ctrl-D) or a piped input stream that is exhausted
        triggers a clean shutdown.
        """
        while self.console_toggle:
            if self.thread_handler.output_bus.pending() > 0:
                self._flush_job_output()

            try:
                raw = input(self._user_prompt()).strip()
            except KeyboardInterrupt:
                print_line()
                warning("Interrupt received.  Type 'exit' to quit.")
                continue
            except EOFError:
                print_line()
                error("EOF received - shutting down.")
                self.shutdown()
                break

            try:
                command, args = self.parse_line(raw)
            except RuntimeError as exc:
                error(str(exc))
                continue

            if not command:
                continue

            self.dispatch(command, args)

    def _flush_job_output(self):
        """
        Print all pending background-job events to the console.

        Called once per REPL iteration so output from running jobs appears
        between prompts without requiring any explicit user action.
        """
        level_handlers = {
            "success": success,
            "error": error,
            "warning": warning,
        }

        for event in self.thread_handler.output_bus.drain():
            level = event.get("level", "info")
            message = event.get("message", "")
            handler = level_handlers.get(level, info)
            handler(message)
