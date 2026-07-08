"""
Terasploit Framework (c) 2026

Author:          4steroth
License:         BSD-3-Clause
Path:            teralibs/tsf/core/payload/uuid/tsf_uuid.py
"""

import hashlib
import os
import struct
import time


class TsfUUID:
    """
    Represents and manages a unique 16-byte Terasploit Framework Payload UUID.

    Binary Layout (16 Bytes, Big-Endian):
        - 8 Bytes: Payload Unique ID (PUID)
        - 1 Byte : Target Platform ID
        - 1 Byte : Target Architecture ID
        - 4 Bytes: Generation Timestamp (Unix Epoch)
        - 2 Bytes: Reserved / XOR Masking space
    """

    # Internal framework metadata maps
    TSF_PLATFORMS = {"windows": 1, "linux": 2, "osx": 3, "android": 4}
    TSF_PLATFORMS_REV = {v: k for k, v in TSF_PLATFORMS.items()}

    TSF_ARCHITECTURES = {"x86": 1, "x64": 2, "arm64": 3}
    TSF_ARCHITECTURES_REV = {v: k for k, v in TSF_ARCHITECTURES.items()}

    def __init__(
        self,
        platform: str = "windows",
        arch: str = "x64",
        puid: bytes | None = None,
        seed: str | None = None,
    ):
        """
        Initializes a TsfUUID tracker tracking instance.
        """
        self.platform = platform.lower()
        self.arch = arch.lower()
        self.timestamp = int(time.time())
        self.xor_key = 0x0000

        # Resolve Platform and Arch IDs
        self.platform_id = self.TSF_PLATFORMS.get(self.platform, 0)
        self.arch_id = self.TSF_ARCHITECTURES.get(self.arch, 0)

        # Handle PUID assignment priority: Explicit -> Seeded -> Random
        if puid:
            if len(puid) != 8:
                raise ValueError("PUID must be exactly 8 bytes long.")
            self.puid = puid
        elif seed:
            # Generate a deterministic 8-byte PUID via SHA-256 hashing
            hash_digest = hashlib.sha256(seed.encode("utf-8")).digest()
            self.puid = hash_digest[:8]
        else:
            self.puid = os.urandom(8)

    def to_raw(self) -> bytes:
        """
        Packs the structural metadata fields into a solid 16-byte Big-Endian sequence.
        """
        return struct.pack(
            ">8sBBIH", self.puid, self.platform_id, self.arch_id, self.timestamp, self.xor_key
        )

    @classmethod
    def from_raw(cls, raw_bytes: bytes) -> "TsfUUID":
        """
        Parses a 16-byte raw sequence back into a structured TsfUUID instance.
        """
        if len(raw_bytes) != 16:
            raise ValueError(f"Invalid raw UUID sequence size. Expected 16, got {len(raw_bytes)}")

        puid, platform_id, arch_id, timestamp, xor_key = struct.unpack(">8sBBIH", raw_bytes)

        # Map integer IDs back to strings
        platform_name = cls.TSF_PLATFORMS_REV.get(platform_id, "unknown")
        arch_name = cls.TSF_ARCHITECTURES_REV.get(arch_id, "unknown")

        # Create instance bypassing default initialization timestamp logic
        instance = cls(platform=platform_name, arch=arch_name, puid=puid)
        instance.platform_id = platform_id
        instance.arch_id = arch_id
        instance.timestamp = timestamp
        instance.xor_key = xor_key

        return instance

    @property
    def puid_hex(self) -> str:
        """
        Returns the hex representation of the 8-byte PUID component.
        """
        return self.puid.hex()
