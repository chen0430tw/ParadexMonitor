"""
Detect ObRegisterCallbacks usage pattern.

ObRegisterCallbacks is the primary mechanism for kernel drivers to
intercept handle operations on processes and threads.  Anti-cheat and
security products use it to strip PROCESS_ALL_ACCESS from handles
opened to protected processes.
"""
from __future__ import annotations

import struct
from .base import Pattern, PatternMatch


class ObCallbackPattern(Pattern):

    @property
    def name(self) -> str:
        return "ob_callback"

    def scan(self, adapter, callgraph=None, depgraph=None) -> list[PatternMatch]:
        matches: list[PatternMatch] = []

        # Step 1: check if ObRegisterCallbacks is imported
        imports = adapter.imports()
        has_import = False
        target_dll = ""
        for dll, funcs in imports.items():
            if "ObRegisterCallbacks" in funcs:
                has_import = True
                target_dll = dll
                break

        if not has_import:
            return matches

        # Step 2: find all IAT call sites for ObRegisterCallbacks
        iat_calls = adapter.iat_calls()
        call_sites: list[dict] = []
        for call in iat_calls:
            if call["target_func"] == "ObRegisterCallbacks":
                call_sites.append(call)

        if not call_sites:
            # Imported but no direct FF 15 call found — might be called indirectly
            matches.append(PatternMatch(
                pattern_name=self.name,
                confidence=0.5,
                location=0,
                details={
                    "dll": target_dll,
                    "import": "ObRegisterCallbacks",
                    "call_sites": [],
                    "note": "Imported but no direct IAT call site found (may be called indirectly)",
                },
                description=(
                    "ObRegisterCallbacks is imported but no direct call site was found. "
                    "The driver may call it through a function pointer or wrapper."
                ),
            ))
            return matches

        # Step 3: for each call site, scan backwards for LEA rcx (the registration struct)
        text_sec = adapter._find_section(".text")
        raw_data = adapter._raw if text_sec else b""
        is64 = adapter._pe.OPTIONAL_HEADER.Magic == 0x20B

        for site in call_sites:
            rva = site["rva"]
            handler_rva = self._find_handler_setup(
                raw_data, text_sec, rva, is64
            ) if text_sec else None

            details = {
                "dll": target_dll,
                "import": "ObRegisterCallbacks",
                "call_site_rva": f"0x{rva:X}",
                "handler_rva": f"0x{handler_rva:X}" if handler_rva else "unknown",
            }

            confidence = 0.9 if handler_rva else 0.75
            desc = (
                f"ObRegisterCallbacks called at RVA 0x{rva:X}. "
                f"Handler at {'0x' + format(handler_rva, 'X') if handler_rva else 'unknown address'}. "
                "This registers a callback to filter handle operations on processes/threads."
            )

            matches.append(PatternMatch(
                pattern_name=self.name,
                confidence=confidence,
                location=rva,
                details=details,
                description=desc,
            ))

        return matches

    @staticmethod
    def _find_handler_setup(
        raw_data: bytes,
        text_sec,
        call_rva: int,
        is64: bool,
    ) -> int | None:
        """Scan backwards from the call site looking for a LEA instruction
        that loads the OB_CALLBACK_REGISTRATION structure address into RCX.

        The struct contains a pointer to the PreOperation / PostOperation
        handler routines.
        """
        if not text_sec or not raw_data:
            return None

        sec_rva = text_sec.VirtualAddress
        raw_offset = text_sec.PointerToRawData

        # Convert call_rva to file offset within .text
        file_off = call_rva - sec_rva + raw_offset

        # Scan backwards up to 64 bytes looking for LEA rcx, [rip+disp]
        # Encoding: 48 8D 0D xx xx xx xx  (REX.W LEA RCX, [RIP+disp32])
        search_start = max(raw_offset, file_off - 64)
        region = raw_data[search_start:file_off]

        for i in range(len(region) - 6, -1, -1):
            # 48 8D 0D = LEA RCX, [RIP+disp32]
            if region[i] == 0x48 and region[i + 1] == 0x8D and region[i + 2] == 0x0D:
                disp = struct.unpack_from("<i", region, i + 3)[0]
                lea_rva = (search_start - raw_offset + sec_rva) + i
                # RIP-relative: target = next_insn_rva + disp
                target_rva = lea_rva + 7 + disp
                if target_rva > 0:
                    return target_rva

        return None
