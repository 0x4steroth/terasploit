"""
Terasploit Framework (c) 2026

Author:          4steroth
License:         BSD-3-Clause
Path:            teralibs/tsf/core/module/options.py
"""

from teralibs.terasploit.framework.console.state import DATASTORE as DS, Option
from teralibs.terasploit.framework.options.validators import OptionType


# Public API


def register_options(scope, options):
    """Register standard module or framework options."""

    # Adjust 'module' to match your primary standard scope identifier
    DS.register(scope, options)


def register_advanced_options(scope, options):
    """Register advanced configuration options for fine-tuning."""

    DS.register(scope, options)


def register_evasion_options(scope, options):
    """Register evasion-specific options to bypass security controls."""

    DS.register(scope, options)


__all__ = [
    "Option",
    "OptionType",
    "register_advanced_options",
    "register_evasion_options",
    "register_options",
]
