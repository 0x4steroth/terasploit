"""
Terasploit Framework (c) 2026

Author:          4steroth
License:         BSD-3-Clause
Path:            add_docstrings.py
"""

import argparse
import re
from pathlib import Path


TEMPLATE = (
    '"""\n'
    "Terasploit Framework (c) 2026\n\n"
    "Author:          4steroth\n"
    "License:         BSD-3-Clause\n"
    "Path:            {relative_path}\n"
    '"""'
)


def fix_file(file_path: Path, root: Path, apply: bool):
    """
    Surgically removes only top-level docstring blocks and adds the new one.
    """
    content = file_path.read_text(encoding="utf-8")
    rel_path = file_path.relative_to(root).as_posix()

    # 1. Separate Shebang
    shebang = ""
    work_content = content
    if content.startswith("#!"):
        match = re.match(r"^(#!.*\n)", content)
        shebang = match.group(1)
        work_content = content[len(shebang) :]

    # 2. Surgical Removal:
    # Find all triple-quote blocks that appear at the VERY TOP of the file.
    # We stop the moment we see something that isn't a docstring or whitespace.
    # This loop keeps removing the first docstring found until no more are at the top.

    modified_content = work_content
    while True:
        # Regex for a docstring block at the start of the current work_content
        match = re.match(r'^\s*("""(.*?)""")', modified_content, re.DOTALL)
        if match:
            # Remove that docstring
            modified_content = modified_content[len(match.group(0)) :].lstrip()
        else:
            # We hit an import, a variable, or code - STOP REMOVING
            break

    # 3. Re-assemble
    new_header = TEMPLATE.format(relative_path=rel_path)
    final_text = f"{shebang}{new_header}\n\n{modified_content.lstrip()}"

    if final_text.strip() != content.strip():
        if apply:
            file_path.write_text(final_text, encoding="utf-8")
            print(f"[+] Fixed: {rel_path}")
        else:
            print(f"[DRY RUN] Would update: {rel_path}")


def process_all(apply: bool):
    """Add docstrings to all module."""
    root = Path(".").resolve()
    for py_file in root.rglob("*.py"):
        if py_file.name == "add_docstrings.py":
            continue
        fix_file(py_file, root, apply)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    process_all(args.apply)
