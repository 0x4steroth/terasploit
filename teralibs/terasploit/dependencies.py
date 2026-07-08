"""
Terasploit Framework (c) 2026

Author:          4steroth
License:         BSD-3-Clause
Path:            teralibs/terasploit/dependencies.py
"""

import dataclasses
import os
from enum import StrEnum
from importlib import metadata

from teralibs.terasploit.framework.services.printf import print_line, success, warning


class Status(StrEnum):
    """Contains the status for DependencyResult."""

    OK = "ok"
    MISSING = "missing"
    INCOMPATIBLE = "incompatible"


@dataclasses.dataclass(slots=True, kw_only=True)
class DependencyResult:
    """
    Outcome of checking a single line from a requirements file.
    """

    name: str
    required_version: str | None = None
    operator: str | None = None
    installed_version: str | None = None
    status: str = Status.MISSING


class DependencyReport:
    """
    Aggregated results from checking an entire requirements file.
    """

    def __init__(self, results):
        self.results = results or []

    def is_clean(self):
        """Return True when every checked package is present and compatible."""
        return all(r.status == Status.OK for r in self.results)

    def print_report(self):
        """
        Print a summary of missing and incompatible packages.

        Prints nothing beyond a success line when all packages are satisfied.
        """
        missing = [r for r in self.results if r.status == Status.MISSING]
        incompatible = [r for r in self.results if r.status == Status.INCOMPATIBLE]

        if not missing and not incompatible:
            success("All dependencies satisfied.")
            print_line()
            return

        if missing:
            warning("Missing dependencies:")
            for result in missing:
                suffix = ""
                if result.required_version:
                    suffix = f"{result.operator}{result.required_version}"
                print_line(f"  - {result.name}{suffix}")

        if incompatible:
            warning("Version conflicts:")
            for result in incompatible:
                print_line(
                    f"  - {result.name}{result.operator}{result.required_version}"
                    f" (installed: {result.installed_version})"
                )

        print_line()


class DependencyChecker:
    """
    Validates a pip requirements file against installed distributions.

    Supported version constraint operators: ==, >=, <=, >, <.
    Lines beginning with # and blank lines are silently ignored.
    """

    OPERATORS: tuple[str, ...] = ("==", ">=", "<=", ">", "<")

    def parse_requirement(self, line):
        """
        Split a requirements line into (name, operator, version).

        Returns (name, None, None) for unconstrained entries such as
        "scapy" with no version specifier attached.
        """
        for operator in self.OPERATORS:
            if operator in line:
                name, version = line.split(operator, 1)
                return name.strip().lower(), operator, version.strip()
        return line.strip().lower(), None, None

    @staticmethod
    def version_satisfies(installed, operator, required):
        """
        Return True when *installed* satisfies the constraint
        operator(required).

        Version strings are compared numerically by splitting on '.' and
        converting each component to an integer tuple.  This avoids the
        lexicographic pitfalls of plain string comparison, where for example
        "2.9" > "2.31" would incorrectly evaluate to True.

        Non-numeric version components (e.g. "1.0a1") fall back to
        lexicographic comparison for that component to remain broadly
        compatible with pre-release version strings.
        """
        if not operator or not required:
            return True

        def _to_tuple(version_str):
            parts = []
            for part in version_str.split("."):
                try:
                    parts.append(int(part))
                except ValueError:
                    # Non-numeric component - keep as string for comparison.
                    parts.append(part)
            return tuple(parts)

        inst_t = _to_tuple(installed)
        req_t = _to_tuple(required)

        comparisons = {
            "==": inst_t == req_t,
            ">=": inst_t >= req_t,
            "<=": inst_t <= req_t,
            ">": inst_t > req_t,
            "<": inst_t < req_t,
        }
        return comparisons.get(operator, True)

    def check_file(self, path):
        """
        Parse path and return a DependencyReport for every listed package.
        """
        if not os.path.isfile(path):
            raise FileNotFoundError(f"Requirements file not found: {path}")

        installed = {
            dist.metadata["Name"].lower(): dist.version for dist in metadata.distributions()
        }

        results = []

        with open(path, encoding="utf-8") as req_file:
            for raw_line in req_file:
                line = raw_line.strip()
                if not line or line.startswith("#"):
                    continue

                name, operator, required_version = self.parse_requirement(line)

                if name not in installed:
                    results.append(
                        DependencyResult(
                            name=name,
                            required_version=required_version,
                            operator=operator,
                            status=Status.MISSING,
                        )
                    )
                    continue

                installed_version = installed[name]
                satisfies = self.version_satisfies(
                    installed_version,
                    operator,
                    required_version,
                )
                status = Status.OK if satisfies else Status.INCOMPATIBLE

                results.append(
                    DependencyResult(
                        name=name,
                        required_version=required_version,
                        operator=operator,
                        installed_version=installed_version,
                        status=status,
                    )
                )

        # Dependencies check result.
        return DependencyReport(results=results)
