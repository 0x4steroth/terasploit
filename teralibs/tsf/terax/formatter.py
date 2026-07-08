"""
Terasploit Framework (c) 2026

Author:          4steroth
License:         BSD-3-Clause
Path:            teralibs/tsf/terax/formatter.py
"""

import base64
import textwrap
from collections.abc import Callable

# Import builders from teralibs/tsf/terax.builder
from teralibs.tsf.core.builder.elf import build_elf  # Unix
from teralibs.tsf.core.builder.pe import build_pe  # Windows


# Internal helpers


def _hex_bytes(data):
    """
    Return a simple hex string of the input bytes, without spaces or newlines.
    """
    return data.hex()


def _escaped(data):
    """
    Return a string of the input bytes with each byte escaped as \\xNN.
    """
    return "".join(f"\\x{b:02x}" for b in data)


def _wrap(text, width=78, indent="  "):
    """Wrap a long hex/escape string into indented lines."""
    return ("\n" + indent).join([text[i : i + width] for i in range(0, len(text), width)])


# Transform formatters
# All formatters share the signature: (data: bytes, arch: str) -> bytes


def fmt_raw(data, _arch=""):
    """Return data unchanged - the identity formatter for raw binary output."""
    return data


def fmt_hex(data, _arch=""):
    """Spaced hex dump, 16 bytes per row - identical to msfvenom -f hex."""
    h = data.hex()
    rows = [h[i : i + 32] for i in range(0, len(h), 32)]
    result = "\n".join(" ".join(r[j : j + 2] for j in range(0, len(r), 2)) for r in rows)
    return result.encode()


def fmt_hexdump(data, _arch=""):
    """xxd-style annotated hex + ASCII dump."""
    lines = []
    for i in range(0, len(data), 16):
        chunk = data[i : i + 16]
        hex_col = " ".join(f"{b:02x}" for b in chunk).ljust(47)
        asc_col = "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in chunk)
        lines.append(f"{i:08x}  {hex_col}  |{asc_col}|")
    return "\n".join(lines).encode()


def fmt_num(data, _arch=""):
    """Comma-separated decimal byte values."""
    return ", ".join(str(b) for b in data).encode()


def fmt_hex_escape(data, _arch=""):
    r"""\\xNN escaped string - e.g. \xfc\x48\x83..."""
    return _escaped(data).encode()


def fmt_c(data, _arch=""):
    """C unsigned char array - identical to msfvenom -f c."""
    hex_vals = ", ".join(f"0x{b:02x}" for b in data)
    lines = textwrap.wrap(hex_vals, width=76)
    body = "\n  ".join(lines)
    out = f"unsigned char buf[] =\n  {body};\nunsigned int buf_len = {len(data)};\n"
    return out.encode()


def fmt_c_string(data, _arch=""):
    r"""C string literal - char buf[] = "\xfc\x48...";"""
    escaped = _escaped(data)
    out = f'char buf[] = "{escaped}";\n'
    return out.encode()


def fmt_csharp(data, _arch=""):
    """C# byte array - msfvenom -f csharp."""
    items = ", ".join(f"0x{b:02x}" for b in data)
    body = textwrap.fill(
        items,
        width=76,
        initial_indent="    ",
        subsequent_indent="    ",
    )
    return f"byte[] buf = new byte[{len(data)}] {{\n{body}\n}};".encode()


def fmt_python(data, _arch=""):
    """Python bytes literal - msfvenom -f python."""
    escaped = _escaped(data)
    chunks = textwrap.wrap(escaped, width=72)
    if len(chunks) == 1:
        out = f'buf  = b"{chunks[0]}"\n'
    else:
        lines = '"\n    b"'.join(chunks)
        out = f'buf  = (\n    b"{lines}"\n)\n'
    out += f"buf_len = {len(data)}\n"
    return out.encode()


def fmt_python_list(data, _arch=""):
    """Python list of integers - buf = [ 0xfc, 0x48, ... ]"""
    vals = ", ".join(f"0x{b:02x}" for b in data)
    lines = textwrap.wrap(vals, width=76)
    body = "\n    ".join(lines)
    out = f"buf = [\n    {body}\n]\n"
    return out.encode()


def fmt_ruby(data, _arch=""):
    """Ruby string literal - msfvenom -f ruby."""
    escaped = _escaped(data)
    chunks = textwrap.wrap(escaped, width=72)
    if len(chunks) == 1:
        out = f'buf = "{chunks[0]}"\n'
    else:
        parts = '" \\\n    "'.join(chunks)
        out = f'buf = "{parts}"\n'
    return out.encode()


def fmt_perl(data, _arch=""):
    """Perl string literal - msfvenom -f perl."""
    rep = _escaped(data)
    chunks = [rep[i : i + 60] for i in range(0, len(rep), 60)]
    lines = ['my $buf = ""'] + [f'       . "{c}"' for c in chunks]
    if lines:
        lines[-1] += ";"
    return "\n".join(lines).encode()


def fmt_bash(data, _arch=""):
    r"""Bash $'\xNN' string variable - msfvenom -f bash."""
    escaped = _escaped(data)
    out = f"$shellcode=$'{escaped}'\n"
    return out.encode()


def fmt_powershell(data, _arch=""):
    """PowerShell [Byte[]] array - msfvenom -f ps1."""
    hex_vals = ",".join(f"0x{b:02x}" for b in data)
    lines = textwrap.wrap(hex_vals, width=76)
    body = ",\n".join(lines)
    out = f"[Byte[]] $buf = {body}\n"
    return out.encode()


def fmt_delphi(data, _arch=""):
    """Delphi / Pascal const byte array."""
    items = ", ".join(f"${b:02x}" for b in data)
    body = textwrap.fill(
        items,
        width=76,
        initial_indent="    ",
        subsequent_indent="    ",
    )
    return (f"var buf: Array[0..{len(data) - 1}] of Byte = (\n{body}\n);").encode()


def fmt_asp(data, _arch=""):
    """Classic ASP / VBScript Array() stub."""
    items = ",".join(str(b) for b in data)
    body = textwrap.fill(
        items,
        width=76,
        initial_indent="    ",
        subsequent_indent="    ",
    )
    return (f"Dim buf\nbuf = Array(\n{body}\n)\nDim size : size = {len(data)}").encode()


def fmt_java(data, _arch=""):
    """Java byte[] array literal."""
    vals = ", ".join(f"(byte)0x{b:02x}" for b in data)
    lines = textwrap.wrap(vals, width=72)
    body = "\n        ".join(lines)
    out = f"byte[] buf = {{\n        {body}\n}};\n"
    return out.encode()


def fmt_base64(data, _arch=""):
    """Standard base64 encoded string."""
    return base64.b64encode(data)


# ELF builder


def fmt_elf(data, arch="x64"):
    """Build a Linux ELF64 executable for the given arch (default: x64)."""
    return build_elf(data, arch or "x64")


def fmt_elf_aarch64(data, _arch=""):
    """Build a Linux ELF64 executable for AArch64."""
    return build_elf(data, "aarch64")


def fmt_elf_x64(data, _arch=""):
    """Build a Linux ELF64 executable for x86-64."""
    return build_elf(data, "x64")


# Minimal Windows PE32+ stub


def fmt_exe(data, arch="x86"):
    """Build a minimal Windows PE executable."""
    return build_pe(data, arch or "x86")


FORMATTERS = {
    "raw": (fmt_raw, "binary", "Raw bytes (write to -o or stdout)"),
    "hex": (fmt_hex, "text", "Spaced hex dump, 16 bytes per line"),
    "hexdump": (fmt_hexdump, "text", "xxd-style annotated hex + ASCII"),
    "num": (fmt_num, "text", "Comma-separated decimal byte values"),
    "hex-escape": (fmt_hex_escape, "text", r"\xNN escaped byte string"),
    "c": (fmt_c, "text", "C unsigned char array"),
    "c-string": (fmt_c_string, "text", "C string literal"),
    "csharp": (fmt_csharp, "text", "C# byte array"),
    "python": (fmt_python, "text", "Python bytes literal"),
    "py": (fmt_python, "text", "Python bytes literal (alias: python)"),
    "python-list": (fmt_python_list, "text", "Python list of integers"),
    "ruby": (fmt_ruby, "text", "Ruby String"),
    "rb": (fmt_ruby, "text", "Ruby String (alias: ruby)"),
    "perl": (fmt_perl, "text", "Perl string"),
    "pl": (fmt_perl, "text", "Perl string (alias: perl)"),
    "bash": (fmt_bash, "text", r"Bash $'\xNN' variable"),
    "sh": (fmt_bash, "text", r"Bash $'\xNN' variable (alias: bash)"),
    "powershell": (fmt_powershell, "text", "PowerShell [Byte[]] array"),
    "ps1": (fmt_powershell, "text", "PowerShell [Byte[]] array (alias: powershell)"),
    "delphi": (fmt_delphi, "text", "Delphi / Pascal const array"),
    "asp": (fmt_asp, "text", "Classic ASP / VBScript Array()"),
    "java": (fmt_java, "text", "Java byte[] literal"),
    "base64": (fmt_base64, "text", "Standard base64 encoded string"),
    "elf": (fmt_elf, "binary", "Linux ELF64 executable"),
    "elf-aarch64": (fmt_elf_aarch64, "binary", "Linux ELF64 executable (AArch64)"),
    "elf-x64": (fmt_elf_x64, "binary", "Linux ELF64 executable (x86-64)"),
    "exe": (fmt_exe, "binary", "Windows PE32+ executable"),
}
