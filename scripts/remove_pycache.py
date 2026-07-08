"""
Terasploit Framework (c) 2026

Author:          4steroth
License:         BSD-3-Clause
Path:            remove_pycache.py
"""

import os
import shutil


def clean_pycache():
    """
    Recursively deletes all '__pycache__' directories in the current folder tree
    and safely modifies the directory list to prevent traversal errors.
    """
    deleted_count = 0
    for root, dirs, _ in os.walk("."):
        if "__pycache__" in dirs:
            pycache_path = os.path.join(root, "__pycache__")
            shutil.rmtree(pycache_path)
            print(f"Deleted: {pycache_path}")
            deleted_count += 1
            # Prevent os.walk from trying to walk into the directory we just deleted
            dirs.remove("__pycache__")

    print(f"\nClean up complete. Removed {deleted_count} __pycache__ directories.")


if __name__ == "__main__":
    clean_pycache()
