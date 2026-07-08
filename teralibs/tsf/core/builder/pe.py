"""
Terasploit Framework (c) 2026

Author:          4steroth
License:         BSD-3-Clause
Path:            teralibs/tsf/core/builder/pe.py
"""

import os
import random
import struct
import sys


# PE Constants
_SEC_ALIGN = 0x1000
_FILE_ALIGN = 0x200

# Machine Types
_IMAGE_FILE_MACHINE_I386 = 0x014C
_IMAGE_FILE_MACHINE_AMD64 = 0x8664

# Characteristics
_IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE = 0x0040
_IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA = 0x0020
_SECTION_MEM_EXECUTE_READ_CODE = 0x60000020

# Builder debug state
DEBUG = False


def _log(msg: str) -> None:
    """
    Outputs build state details clearly to standard error if DEBUG is enabled.
    """
    if DEBUG:
        sys.stderr.write(f"[~] {msg}\n")


def _template_path(arch: str) -> str:
    """
    Returns the absolute path to the target Windows PE template file based on architecture.
    """
    filename = f"template_{arch}_windows.exe"
    return os.path.join(
        os.path.dirname(
            os.path.dirname(
                os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
            )
        ),
        "data",
        "template",
        filename,
    )


def _align(n: int, a: int) -> int:
    """
    Aligns an integer boundary up to the next multiple of the specified alignment.=
    """
    return (n + a - 1) & ~(a - 1)


def load_template(file_path: str) -> bytes:
    """
    Reads a PE template file into memory for binary manipulation.=
    """
    _log(f"Loading template binary from: {file_path}")
    with open(file_path, "rb") as f:
        data = f.read()
    _log(f"Successfully read {len(data)} bytes from template file.")
    return data


def _get_arch_offsets(machine: int) -> tuple[int, int, int, str]:
    """
    Returns architecture-specific structural offsets for Optional Header fields.
    """
    if machine == _IMAGE_FILE_MACHINE_AMD64:
        return 16, 24, 70, "Q"
    elif machine == _IMAGE_FILE_MACHINE_I386:
        return 16, 28, 68, "I"
    else:
        raise ValueError(f"Unsupported machine architecture: {hex(machine)}")


def build_pe(code: bytes, arch: str = "x64") -> bytes:
    """
    Injects code into a Windows PE template by appending a new executable
    section, updating fields, and dynamically patching stub displacement offsets.
    """
    if isinstance(arch, list):
        arch = arch[0]

    normalized_arch = arch.lower().strip()
    if normalized_arch not in ("x86", "x64"):
        raise ValueError("Invalid architecture string. Choose 'x86' or 'x64'.")

    _log(f"Initiating build payload size: {len(code)} bytes for target {normalized_arch}.")
    pe = bytearray(load_template(_template_path(normalized_arch)))

    if pe[0:2] != b"MZ":
        raise ValueError("Invalid DOS header signature (Missing 'MZ').")

    e_lfanew = struct.unpack_from("<I", pe, 0x3C)[0]
    if pe[e_lfanew : e_lfanew + 4] != b"PE\x00\x00":
        raise ValueError("Invalid PE signature.")

    machine = struct.unpack_from("<H", pe, e_lfanew + 4)[0]
    if normalized_arch == "x64" and machine != _IMAGE_FILE_MACHINE_AMD64:
        raise ValueError("Template machine mismatch: expected x64 (0x8664).")
    elif normalized_arch == "x86" and machine != _IMAGE_FILE_MACHINE_I386:
        raise ValueError("Template machine mismatch: expected x86 (0x014C).")

    opt_hdr_start = e_lfanew + 24
    ep_rel_off, _, dll_chars_rel_off, _ = _get_arch_offsets(machine)

    num_sec_off = e_lfanew + 6
    hdr_size_off = opt_hdr_start + 60
    img_size_off = opt_hdr_start + 56
    dll_chars_off = opt_hdr_start + dll_chars_rel_off

    opt_size = struct.unpack_from("<H", pe, e_lfanew + 20)[0]
    sec_tbl = opt_hdr_start + opt_size
    num_sections = struct.unpack_from("<H", pe, num_sec_off)[0]

    original_file_end = len(pe)
    last_va = 0
    last_vs = 0

    for i in range(num_sections):
        s_offset = sec_tbl + (i * 40)
        s_va = struct.unpack_from("<I", pe, s_offset + 12)[0]
        s_vs = struct.unpack_from("<I", pe, s_offset + 8)[0]
        s_ro = struct.unpack_from("<I", pe, s_offset + 20)[0]
        s_rs = struct.unpack_from("<I", pe, s_offset + 16)[0]

        if (s_ro + s_rs) > original_file_end:
            original_file_end = s_ro + s_rs
        if s_va > last_va:
            last_va = s_va
            last_vs = s_vs

    new_va = _align(last_va + last_vs, _SEC_ALIGN)
    new_roff = _align(original_file_end, _FILE_ALIGN)
    new_vs = len(code)
    new_rs = _align(len(code), _FILE_ALIGN)

    # Disable ASLR base characteristics flags to allow reliable static mappings
    dll_chars = struct.unpack_from("<H", pe, dll_chars_off)[0]
    mask = ~(_IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE | _IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA)
    struct.pack_into("<H", pe, dll_chars_off, dll_chars & mask)

    # Handle structural validation check for SizeOfHeaders boundaries
    new_hdr_start = sec_tbl + num_sections * 40
    new_hdr_end = new_hdr_start + 40
    orig_size_of_headers = struct.unpack_from("<I", pe, hdr_size_off)[0]

    if new_hdr_end > orig_size_of_headers:
        new_size_of_headers = _align(new_hdr_end, _FILE_ALIGN)
        struct.pack_into("<I", pe, hdr_size_off, new_size_of_headers)

        shift_amount = new_size_of_headers - orig_size_of_headers
        header_data = pe[:orig_size_of_headers]
        body_data = pe[orig_size_of_headers:]

        pe = bytearray(header_data + (b"\x00" * shift_amount) + body_data)
        new_roff += shift_amount

        for i in range(num_sections):
            s_offset = sec_tbl + (i * 40)
            s_ro = struct.unpack_from("<I", pe, s_offset + 20)[0]
            struct.pack_into("<I", pe, s_offset + 20, s_ro + shift_amount)

    # Append new section payload mapping structure
    section_name = "." + "".join(random.choice("abcdefghijklmnopqrstuvwxyz") for _ in range(4))
    new_hdr = (
        section_name.encode().ljust(8, b"\x00")
        + struct.pack("<I", new_vs)
        + struct.pack("<I", new_va)
        + struct.pack("<I", new_rs)
        + struct.pack("<I", new_roff)
        + b"\x00" * 12
        + struct.pack("<I", _SECTION_MEM_EXECUTE_READ_CODE)
    )
    pe[new_hdr_start:new_hdr_end] = new_hdr

    # Sync total section metrics and size indicators
    struct.pack_into("<H", pe, num_sec_off, num_sections + 1)
    new_image_size = _align(new_va + new_vs, _SEC_ALIGN)
    struct.pack_into("<I", pe, img_size_off, new_image_size)

    # Update entry point to point directly to the newly added code section
    pe_entry_point_off = opt_hdr_start + ep_rel_off
    struct.pack_into("<I", pe, pe_entry_point_off, new_va)

    # Assemble the final executable payload body securely
    clean_template_body = bytes(pe)
    if len(clean_template_body) < new_roff:
        clean_template_body = clean_template_body.ljust(new_roff, b"\x00")
    else:
        clean_template_body = clean_template_body[:new_roff]

    final_payload = clean_template_body + code.ljust(new_rs, b"\x00")
    return final_payload
