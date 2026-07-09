"""
Terasploit Framework (c) 2026

Author:          4steroth
License:         BSD-3-Clause
Path:            teralibs/terasploit/framework/services/banner.py
"""

from teralibs.terasploit.framework.services.printf import print_line


# Module category
CATEGORIES = ("exploit", "auxiliary", "payload", "encoder", "post", "nop", "evasion")

# Banner file list
BANNER = """
\033[1;91m
 __                                 __         __ __
|  |_.-----.----.---.-.-----.-----.|  |.-----.|__|  |_
|   _|  -__|   _|  _  |__ --|  _  ||  ||  _  ||  |   _|
|____|_____|__| |___._|_____|   __||__||_____||__|____|
                            |__|  \033[1;33;41m 0x4steroth \033[0m
"""


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

    print_line(BANNER)
    print_line("Copyright (c) 2026 0x4steroth\nLicense: BSD-3-Clause\n")

    prefix = "Modules: "
    print_line(
        prefix + f"{counts['exploit']} exploit · "
        f"{counts['auxiliary']} auxiliary · "
        f"{counts['payload']} payload"
    )

    print_line(
        " " * len(prefix) + f"{counts['encoder']} encoder · "
        f"{counts['post']} post · "
        f"{counts['nop']} nop · "
        f"{counts['evasion']} evasion",
        "\n",
    )
