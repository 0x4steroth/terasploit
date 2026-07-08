"""
Terasploit Framework (c) 2026

Author:          4steroth
License:         BSD-3-Clause
Path:            teralibs/terasploit/framework/services/tables.py
"""

import dataclasses
import textwrap
from dataclasses import field

from teralibs.terasploit.framework.services.printf import (
    GREEN,
    RED,
    RESET,
    print_line,
    warning,
)


class Constants:
    """Holds the constant variable of tables."""

    # Default maximum width used when wrapping long description text
    DEFAULT_DESC_WRAP = 80

    # Default maximum width for the Current Setting column.
    # Set wider than DESC_WRAP so paths, URIs, and comma-separated lists
    # get reasonable room before wrapping.
    DEFAULT_VAL_WRAP = 16

    # Extra spacing added around table column content for readability
    TABLE_PADDING = 3

    # String used to separate rendered table columns
    COL_SEP = "  "

    # Cached reference to the global module index/registry instance
    MODULE_INDEX = None


def set_module_index(index):
    """
    Register the active ModuleIndex so metadata lookups work.

    """
    Constants.MODULE_INDEX = index


@dataclasses.dataclass
class TableSchema:
    """
    Layout specification for a terminal table column set.

    """

    headers: tuple[str, ...]
    min_widths: list[int] = field(default_factory=list)
    wrap_widths: list[int] = field(default_factory=list)
    padding: int = Constants.TABLE_PADDING

    def __post_init__(self):
        self.headers = tuple(self.headers)
        self.min_widths = list(self.min_widths)
        self.wrap_widths = list(self.wrap_widths)


class TableRenderer:
    """
    Render a list of row tuples using a TableSchema.
    """

    def __init__(self, schema):
        self._schema = schema

    @property
    def schema(self):
        """
        Return the active table schema.
        """
        return self._schema

    def _fmt_cell(
        self,
        text,
        width,
        is_last=False,
    ):
        """
        Format a single table cell.
        """
        if is_last:
            return text

        return f"{text:<{width}}"

    def _compute_widths(self, rows):
        """
        Compute final per-column widths from content, headers, and min widths.
        """
        schema = self._schema
        widths = list(schema.min_widths)
        n_cols = len(schema.headers)

        for idx in range(n_cols):
            widths[idx] = max(widths[idx], len(schema.headers[idx]))

        for row in rows:
            for idx, cell in enumerate(row):
                if idx >= n_cols:
                    break

                if schema.wrap_widths[idx] == 0:
                    widths[idx] = max(widths[idx], len(str(cell)))

        return widths

    def _wrap_cell(self, text, col_idx):
        """
        Split *text* into lines for the given column index.
        """
        wrap_at = self._schema.wrap_widths[col_idx]

        if not wrap_at or len(text) <= wrap_at:
            return [text]

        return textwrap.wrap(text, width=wrap_at) or [""]

    def _render_header(
        self,
        widths,
    ):
        """
        Render table header and separator.
        """
        schema = self._schema
        pad = " " * schema.padding
        n_cols = len(schema.headers)

        header_parts = [
            self._fmt_cell(
                schema.headers[idx],
                widths[idx],
                is_last=idx == n_cols - 1,
            )
            for idx in range(n_cols)
        ]

        sep_parts = [
            self._fmt_cell(
                "-" * len(schema.headers[idx]),
                widths[idx],
                is_last=idx == n_cols - 1,
            )
            for idx in range(n_cols)
        ]

        print_line(pad + Constants.COL_SEP.join(header_parts))
        print_line(pad + Constants.COL_SEP.join(sep_parts))

    def _render_row(
        self,
        row,
        widths,
    ):
        """
        Render a single wrapped row.
        """
        schema = self._schema
        pad = " " * schema.padding
        n_cols = len(schema.headers)

        wrapped = [
            self._wrap_cell(str(row[idx]) if idx < len(row) else "", idx) for idx in range(n_cols)
        ]

        n_lines = max(len(lines) for lines in wrapped)

        for line_idx in range(n_lines):
            line_parts = []

            for col_idx in range(n_cols):
                col_lines = wrapped[col_idx]

                if line_idx < len(col_lines):
                    cell_text = col_lines[line_idx]
                else:
                    cell_text = "." if line_idx > 0 else ""

                line_parts.append(
                    self._fmt_cell(
                        cell_text,
                        widths[col_idx],
                        is_last=col_idx == n_cols - 1,
                    )
                )

            print_line(pad + Constants.COL_SEP.join(line_parts))

    def render(self, rows):
        """
        Print the complete table to the console.
        """
        widths = self._compute_widths(rows)

        self._render_header(widths)

        for row in rows:
            self._render_row(row, widths)


def _dotted_to_path(dotted):
    """
    Convert a dotted module name to its slash-separated display form.
    """
    return dotted.replace(".", "/")


def _load_module_meta(dotted):
    """
    Read RANK from a module's TerasploitModule class.
    """
    rank = "normal"

    if Constants.MODULE_INDEX is None:
        return rank

    try:
        mod = Constants.MODULE_INDEX.load(dotted)
        if mod is None:
            return rank

        cls = getattr(mod, "TerasploitModule", None)
        if cls is None:
            return rank

        rank = getattr(cls, "RANK", rank)
        if not isinstance(rank, str) and hasattr(rank, "name"):
            rank = rank.name.lower()
        else:
            rank = str(rank).lower()

    except Exception:  # pylint: disable=broad-except
        pass

    return rank


def options_table(
    section_title,
    defs,
    vals,
):
    """
    Render a block of configurable options to the terminal.

    """
    rows = []
    for _key, opt in sorted(defs.items()):
        current = vals.get(_key)
        cur_str = str(current) if current is not None else ""
        req_str = "yes" if opt.required else "no"
        rows.append((opt.name, cur_str, req_str, opt.desc))

    print_line()
    print_line(f"{section_title}:")
    print_line()

    if not rows:
        print_line("   (no options)")
        print_line()
        return

    longest_name = max(len(r[0]) for r in rows)

    schema = TableSchema(
        headers=("Name", "Current Setting", "Required", "Description"),
        min_widths=[longest_name + 2, 16, 8, 20],
        wrap_widths=[0, Constants.DEFAULT_VAL_WRAP, 0, Constants.DEFAULT_DESC_WRAP],
        padding=Constants.TABLE_PADDING,
    )
    TableRenderer(schema).render(rows)


def current_settings_table(section_title, defs, vals):
    """
    Render a compact "current settings" view for the active module.
    """
    rows = []
    for _key, opt in sorted(defs.items()):
        current = vals.get(_key)
        if current is None or str(current).strip() == "":
            continue
        rows.append((opt.name, str(current)))

    print_line()
    print_line(f"{section_title}:")
    print_line()

    if not rows:
        print_line("   (no options are currently set)")
        print_line()
        return

    longest_name = max(len(r[0]) for r in rows)
    longest_val = max(len(r[1]) for r in rows)

    # Only apply value wrapping when a value actually exceeds the wrap width
    # to avoid wrapping short, readable values unnecessarily.
    val_wrap = Constants.DEFAULT_VAL_WRAP if longest_val > Constants.DEFAULT_VAL_WRAP else 0

    schema = TableSchema(
        headers=("Name", "Current Setting"),
        min_widths=[longest_name + 2, 16],
        wrap_widths=[0, val_wrap],
        padding=Constants.TABLE_PADDING,
    )
    TableRenderer(schema).render(rows)


def targets_table(targets):
    """
    Render the targets declared by the active module.
    """
    if not targets:
        return

    print_line()
    print_line("Targets:")
    print_line()

    w_id = max(len("Id"), max(len(str(t[0])) for t in targets))
    w_name = max(len("Name"), max(len(str(t[1])) for t in targets))

    print_line(f"   {'Id':<{w_id}}  {'Name':<{w_name}}")
    print_line(f"   {'-' * 2:<{w_id}}  {'-' * 4}")

    for tid, tname in targets:
        print_line(f"   {tid!s:<{w_id}}  {tname!s:<{w_name}}")


def modules_table(modules):
    """
    Render a listing of modules with index, path, rank, and description.
    """
    if not modules:
        warning("No modules found.")
        return

    rows = []
    for idx, dotted in enumerate(modules):
        rank = _load_module_meta(dotted)
        display_name = _dotted_to_path(dotted)
        rows.append((str(idx), display_name, rank))

    w_idx = max(len("#"), max(len(r[0]) for r in rows))
    w_name = max(len("Name"), max(len(r[1]) for r in rows))
    w_rank = max(len("Rank"), max(len(r[2]) for r in rows))

    # Description is truncated in the header row calculation but rendered
    # with wrapping in the body so it never forces an unreadable wide table.
    print_line()
    print_line(f"   {'#':<{w_idx}}  {'Path':<{w_name + 3}}  {'Rank':<{w_rank}}")
    print_line(f"   {'-':<{w_idx}}  {'-' * 4:<{w_name + 3}}  {'-' * 4:<{w_rank}}")

    for idx_str, name, _rank in rows:
        if _rank in ("excellent", "great", "high"):
            rank_display = f"{GREEN}{_rank}{RESET}"
        elif _rank in ("normal", "good", "manual"):
            rank_display = _rank
        elif _rank in ("low", "bad", "poor"):
            rank_display = f"{RED}{_rank}{RESET}"
        else:
            rank_display = _rank or "unknown"

        # Pad using the raw (no-ANSI) rank so column widths stay consistent.
        rank_label = _rank or "unknown"
        rank_padded = rank_display + " " * max(0, w_rank - len(rank_label))

        print_line(f"   {idx_str:<{w_idx}}  {name:<{w_name + 3}}  {rank_padded}")
