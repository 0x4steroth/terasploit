"""
Terasploit Framework (c) 2026

Author:          4steroth
License:         BSD-3-Clause
Path:            teralibs/tsf/core/payload/uuid/options.py
"""

from teralibs.tsf.core.module.base import Base
from teralibs.tsf.core.payload.uuid.tsf_uuid import TsfUUID


class PayloadUUIDOptions(Base):
    """
    Provides datastore option definitions and helper methods for payload modules
    that support unique tracking identifiers (UUIDs).
    """

    # Minimum URI length required to carry an embedded URL-safe base64 UUID
    URI_CHECKSUM_UUID_MIN_LEN = 22

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.register_advanced_options(
            [
                self.opt(
                    "PayloadUUIDSeed",
                    "",
                    False,
                    "A string to use when generating the payload UUID (deterministic)",
                    self.otype.STRING,
                ),
                self.opt(
                    "PayloadUUIDRaw",
                    "",
                    False,
                    "A hex string representing the raw 8-byte PUID value for the UUID",
                    self.otype.STRING,
                ),
                self.opt(
                    "PayloadUUIDName",
                    "",
                    False,
                    "A human-friendly name to reference this unique payload (requires tracking)",
                    self.otype.STRING,
                ),
                self.opt(
                    "PayloadUUIDTracking",
                    False,
                    True,
                    "Whether or not to automatically register generated UUIDs",
                    self.otype.BOOL,
                ),
            ]
        )

    def generate_uri_uuid_mode(
        self, mode: str, length: int | None = None, uuid: TsfUUID | None = None
    ) -> str:
        """
        Generates a URI string with a structural checksum and incorporates an
        embedded UUID if space limits permit.
        """
        sum_val = self.uri_checksum_lookup(mode)

        # Check if the requested length configuration restricts embedding a full UUID string
        if length and length < self.URI_CHECKSUM_UUID_MIN_LEN:
            if self.datastore.get("PayloadUUIDSeed") or self.datastore.get("PayloadUUIDRaw"):
                raise ValueError(
                    "A PayloadUUIDSeed or PayloadUUIDRaw value was specified, "
                    "but this payload configuration doesn't have enough room for a UUID."
                )
            return "/" + self.generate_uri_checksum(sum_val, length, prefix="")

        if uuid is None:
            uuid = self.generate_payload_uuid()

        # Intertwines the checksum and UUID bytes to form the target URL slug
        uri = self.generate_uri_uuid(sum_val, uuid, length)

        return uri

    def generate_payload_uuid(self, conf: dict | None = None) -> TsfUUID:
        """
        Parses datastore settings to build and return a unique payload identifier instance.
        """
        if conf is None:
            conf = {}

        # Default back to current framework module specifications if missing
        conf.setdefault("arch", getattr(self, "arch", "x64"))
        conf.setdefault("platform", getattr(self, "platform", "windows"))

        # Map user-defined seed patterns
        if self.datastore.get("PayloadUUIDSeed"):
            conf["seed"] = str(self.datastore.get("PayloadUUIDSeed"))

        # Map explicitly hardcoded 8-byte hex seeds
        if self.datastore.get("PayloadUUIDRaw"):
            puid_raw_hex = str(self.datastore.get("PayloadUUIDRaw"))
            try:
                puid_raw = bytes.fromhex(puid_raw_hex)
            except ValueError:
                raise ValueError("The PayloadUUIDRaw value must be valid hex characters.")

            if len(puid_raw) != 8:
                raise ValueError(
                    "The PayloadUUIDRaw value must represent exactly 8 raw bytes (16 hex chars)."
                )

            conf.pop("seed", None)
            conf["puid"] = puid_raw

        if self.datastore.get("PayloadUUIDName") and not self.datastore.get("PayloadUUIDTracking"):
            raise ValueError(
                "The PayloadUUIDName option is ignored unless PayloadUUIDTracking is enabled."
            )

        # Create and return structural representation
        return TsfUUID(**conf)
