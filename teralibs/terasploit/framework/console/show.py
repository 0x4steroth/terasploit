"""
Terasploit Framework (c) 2026

Author:          4steroth
License:         BSD-3-Clause
Path:            teralibs/terasploit/framework/console/show.py
"""

from teralibs.terasploit.framework.console.helpers import (
    _category_of,
    _filter_compatible,
    _to_path,
)
from teralibs.terasploit.framework.console.terasploit import Terasploit
from teralibs.terasploit.framework.services import tables as tbl
from teralibs.terasploit.framework.services.printf import (
    GREEN,
    RESET,
    info,
    print_line,
    warning,
)


# Category label mapping for section titles in show options
_CATEGORY_LABELS = {
    "exploit": "Exploit",
    "auxiliary": "Auxiliary",
    "payload": "Payload",
    "encoder": "Encoder",
    "post": "Post",
    "nop": "NOP",
    "evasion": "Evasion",
}


class ConsoleRenderer(Terasploit):
    """
    Mixin that contributes all show sub-command handlers to CLi.

    Relies on self.module_storage, self.datastore, and
    self.modules being provided by the host class (Terasploit).
    """

    def _cmd_show(self, args):
        """
        Dispatch show sub-commands to their respective display methods.

        A sub-command argument is required.  Bare show with no argument
        prints a usage hint rather than silently running show options.
        """
        if not args:
            warning(
                "Usage: show <target>  -  "
                "options, advanced, evasion, targets, all, exploits, "
                "payloads, auxiliary, encoders, post, nops."
            )
            return

        sub = args[0].lower()

        sub_dispatch = {
            "options": self.show_options,
            "advanced": self.show_advanced,
            "evasion": self.show_evasion,
            "targets": self.show_targets,
            "all": lambda: self.show_category(None),
            "modules": lambda: self.show_category(None),
            "exploits": lambda: self.show_category("exploit"),
            "payloads": lambda: self.show_category("payload"),
            "auxiliary": lambda: self.show_category("auxiliary"),
            "encoders": lambda: self.show_category("encoder"),
            "post": lambda: self.show_category("post"),
            "nops": lambda: self.show_category("nop"),
            "evasions": lambda: self.show_category("evasion"),
        }

        handler = sub_dispatch.get(sub)

        if handler is None:
            warning(
                f"Unknown show target '{sub}'.  "
                "Try: options, advanced, evasions, targets, all, exploits, "
                "payloads, auxiliary, encoders, post, nops."
            )
            return

        # All module related keys
        module_related_keys = (
            "exploits",
            "auxiliary",
            "payloads",
            "encoders",
            "post",
            "nops",
            "evasions",
            "all",
        )

        # Execute the context specific method.
        if sub in module_related_keys:
            print_line(f'\nShow: "{sub}"\n')

        # Execute the sub handler.
        handler()

        # We check first before giving the hint, no need to give hint
        # on out of context show method such as show framework options.
        entry = self.module_storage.module()
        if entry is not None and sub not in module_related_keys:
            # A little guide help for users.
            print_line("\n")
            print_line("View the full module info with the", f"command '{GREEN}info{RESET}'.\n")

        if entry is None or sub in module_related_keys:
            print_line()

    def show_options(self):
        """
        Display basic module options, basic payload options, and targets.

        When no module is loaded, the framework core options are shown
        so the user can review global defaults before selecting a module.
        """
        entry = self.module_storage.module()

        if entry is None:
            self.show_framework_options()
            return

        category = _category_of(entry.name)
        label = _CATEGORY_LABELS.get(category, category.capitalize())
        if category in ("exploit", "auxiliary", "payload", "post", "evasion"):
            mod_defs = self.datastore.definitions("module")
            mod_vals = self.datastore.all("module")

            # For post modules SESSION is injected by the loader into the
            # datastore directly (not via obj.OPTIONS), so we gate on
            # mod_defs rather than entry.module.OPTIONS.
            has_options = entry.module.OPTIONS if category != "post" else bool(mod_defs)

            if has_options and mod_defs:
                tbl.options_table(
                    f"{label} options ({_to_path(entry.name)})",
                    mod_defs,
                    mod_vals,
                )

        pay_entry = self.module_storage.payload()
        if pay_entry is not None:
            if category == "exploit" and entry.module.OPTIONS:
                print_line()

            pay_defs = self.datastore.definitions("payload")
            pay_vals = self.datastore.all("payload")

            if pay_defs:
                tbl.options_table(
                    f"Payload options ({_to_path(pay_entry.name)})",
                    pay_defs,
                    pay_vals,
                )

        elif not self.datastore.definitions("module"):
            print_line()
            print_line(f"{label} options ({_to_path(entry.name)}):")
            print_line()
            print_line("   (no options available for this module)")
            print_line()

        enc_entry = self.module_storage.encoder()
        if enc_entry is not None:
            if pay_entry is not None:
                print_line()

            enc_defs = self.datastore.definitions("encoder")
            enc_vals = self.datastore.all("encoder")
            if enc_defs:
                tbl.options_table(
                    f"Encoder options ({_to_path(enc_entry.name)})",
                    enc_defs,
                    enc_vals,
                )

        targets = getattr(entry.module, "TARGET", None)
        if targets:
            print_line()
            tbl.targets_table(targets)

    def show_advanced(self):
        """
        Display advanced options for the active module and its payload.

        Module advanced options cover driver-level knobs (ExitOnSession,
        WfsDelay, VERBOSE, WORKSPACE, etc.) plus any extras the module
        declares in ADVANCED_OPTIONS.  Payload advanced options cover
        transport-level knobs (StagerRetryCount, ReverseAllowProxy, etc.)
        plus any payload-declared extras.

        Evasion options (declared via EVASION_OPTIONS) are intentionally
        excluded here and shown separately by show evasion.

        When no module is loaded, the framework core options are shown
        instead so the user can configure global console behaviour.
        """
        entry = self.module_storage.module()
        if entry is None:
            warning("No module loaded.")
            return

        # We will skip encoder because encoders cannot be use anyways.
        # When you use the command "use" on encoder, it will just set
        # it as the current encoder.
        category = _category_of(entry.name)
        if category == "exploit":
            self.show_module_advanced(entry)
            self.show_payload_advanced()
            self.show_encoder_summary()
            return

        if category == "payload":
            self.show_payload_advanced()
            self.show_encoder_summary()
            return

        self.show_module_advanced(entry)

    def show_module_advanced(self, entry):
        """Render the advanced options table for the active module."""

        name = entry.name
        category = _category_of(name)  # first segment only

        label = _CATEGORY_LABELS.get(category, category.capitalize())
        title = f"{label} advanced options ({_to_path(name)})"

        defs = self.datastore.definitions("module_advanced")
        vals = self.datastore.all("module_advanced")

        if defs:
            tbl.options_table(title, defs, vals)
        else:
            print_line()
            info(f"No advanced options for {_to_path(name)}.")

    def show_payload_advanced(self):
        """Render the advanced options table for the active payload, if any."""
        pay_entry = self.module_storage.payload()
        if pay_entry is None:
            return

        defs = self.datastore.definitions("payload_advanced")
        vals = self.datastore.all("payload_advanced")
        if defs:
            title = f"Payload advanced options ({_to_path(pay_entry.name)})"
            tbl.options_table(title, defs, vals)

    def show_encoder_summary(self):
        """Print a one-line summary of the active encoder, if any."""
        enc_entry = self.module_storage.encoder()
        if enc_entry is None:
            return

        enc_obj = enc_entry.module
        rank = enc_obj.RANK
        rank_lbl = getattr(rank, "label", lambda: str(rank))()
        arch_str = ", ".join(enc_obj.ARCH or []) or "generic"
        description = getattr(enc_obj, "DESCRIPTION", "")

        print_line(
            f"\nActive encoder: {_to_path(enc_entry.name)} "
            f"[rank={rank_lbl}, arch={arch_str}]\n"
            f"Description   : {description[:90]}"
        )

    # Evasion option display

    def show_evasion(self):
        """
        Display evasion options for the active module and its payload.

        Evasion options are registered from a module's EVASION_OPTIONS class
        attribute into the module_evasion scope, and from a payload's
        EVASION_OPTIONS into the payload_evasion scope.

        When no module is loaded, the framework core options are shown
        instead so the user can configure global console behaviour.

        Mirrors the Metasploit show evasion sub-command which renders
        options registered via register_evasion_options.
        """
        entry = self.module_storage.module()
        if entry is None:
            self.show_category("evasion")
            return

        category = _category_of(entry.name)
        if category == "exploit":
            self.show_module_evasion(entry)
            self.show_payload_evasion()
            return
        if category == "payload":
            self.show_payload_evasion()
            return

        self.show_module_evasion(entry)

    def show_module_evasion(self, entry):
        """Render the evasion options table for the active module."""
        name = entry.name
        category = _category_of(name)
        label = _CATEGORY_LABELS.get(category, category.capitalize())
        title = f"{label} evasion options ({_to_path(name)})"

        defs = self.datastore.definitions("module_evasion")
        vals = self.datastore.all("module_evasion")

        if defs:
            tbl.options_table(title, defs, vals)
        else:
            print_line()
            info(f"No evasion options for {_to_path(name)}.")

    def show_payload_evasion(self):
        """Render the evasion options table for the active payload, if any."""
        pay_entry = self.module_storage.payload()
        if pay_entry is None:
            return

        defs = self.datastore.definitions("payload_evasion")
        vals = self.datastore.all("payload_evasion")
        if defs:
            title = f"Payload evasion options ({_to_path(pay_entry.name)})"
            tbl.options_table(title, defs, vals)

    def show_framework_options(self):
        """
        Display the framework core options stored in the framework scope.

        These settings control global console behaviour and persist across
        module reloads.  Use setg / unsetg to change them.
        """
        fw_defs = self.datastore.definitions("framework")
        fw_vals = self.datastore.all("framework")

        if fw_defs:
            tbl.options_table("Framework core options", fw_defs, fw_vals)

        else:
            print_line()
            info("No framework options are registered.")
            print_line()

    def show_targets(self):
        """
        Display only the targets declared by the active module.

        Prints an error when no module is loaded or the module has no
        TARGET list rather than printing an empty table.
        """
        entry = self.module_storage.module()
        if entry is None:
            warning("No module loaded.")
            return

        targets = getattr(entry.module, "TARGET", [])

        if not targets:
            warning("This module does not declare any targets.")
            return

        tbl.targets_table(targets)

    def show_category(self, category):
        """
        Display a modules table filtered by category.

        When category is None all indexed modules are shown.

        When an exploit/auxiliary module is active and category is
        'payload' or 'encoder', only compatible modules are shown -
        those whose ARCH and PLATFORM intersect with the active module's
        declared ARCH and PLATFORM.  Mirrors Metasploit's behaviour of
        narrowing show payloads / show encoders to the module
        context when one is loaded.
        """
        all_modules = self.modules.list()

        if category is not None:
            filtered = [m for m in all_modules if _category_of(m) == category]
        else:
            filtered = all_modules

        entry = self.module_storage.module()
        if entry is not None and category in ("payload", "encoder"):
            filtered = _filter_compatible(filtered, entry.module, category)
            if not filtered:
                info(f"No compatible {category}s found for the active module. Showing all instead.")
                filtered = [m for m in all_modules if _category_of(m) == category]
        tbl.modules_table(filtered)

        # Guide for users.
        print_line(
            "\n\nInteract with a module by path using",
            f"the command '{GREEN}use <module_path>{RESET}'",
        )
