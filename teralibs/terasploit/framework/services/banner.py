"""
Terasploit Framework (c) 2026

Author:          4steroth
License:         BSD-3-Clause
Path:            teralibs/terasploit/framework/services/banner.py
"""

import random
from pathlib import Path

from teralibs.terasploit.framework.services.printf import print_line
from teralibs.terasploit.metadata import VERSION


# Module category
CATEGORIES = ("exploit", "auxiliary", "payload", "encoder", "post", "nop", "evasion")

# Banner file list
BANNERS = ["classic.txt", "cowsay.txt"]

# Loaded banners
LOADED_BANNERS = []

# Resolve the absolute path of the current file's directory
here = Path(__file__).resolve().parent

for file in BANNERS:
    banner_file = here.parents[3] / "data" / "logos" / file
    try:
        with open(banner_file, encoding="utf-8") as _banner:
            raw_content = _banner.read()

            # Convert literal string "\033" or "\e" into the true ESC byte
            processed_content = (
                raw_content.replace("\\033", "\033").replace("\\e", "\033").replace("\\n", "\n")
            )

            LOADED_BANNERS.append(processed_content)

    except FileNotFoundError:
        print_line(f"Warning: Could not find banner file at {banner_file}")


def display_banner(module_list):
    """
    Print the ASCII banner, legal disclaimer, and per-category module counts.
    """
    counts = {cat: 0 for cat in CATEGORIES}

    for name in module_list:
        for cat in CATEGORIES:
            if name == cat or name.startswith(f"{cat}."):
                counts[cat] += 1
                break

    print_line(random.choice(LOADED_BANNERS))

    def fixed_line(prefix: str, content: str, width: int = 65) -> str:
        """Print lines in fixed width."""
        return f"{prefix}{content:<{width - len(prefix) - 1}}]"

    print_line(
        fixed_line(" " * 6 + "-=[ ", f"\033[33mterasploit-framework {VERSION}\033[0m", width=74)
    )
    print_line(
        fixed_line(
            "+ -- --=[ ",
            (
                f"{counts['exploit']} exploit - "
                f"{counts['auxiliary']} auxiliary - "
                f"{counts['payload']} payload"
            ),
        ),
    )
    print_line(
        fixed_line(
            "+ -- --=[ ",
            (
                f"{counts['encoder']} encoder - "
                f"{counts['post']} post - "
                f"{counts['nop']} nop - "
                f"{counts['evasion']} evasion"
            ),
        ),
        "\n",  # New line for cosmetics.
    )
