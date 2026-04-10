"""
Detect CmRegisterCallbackEx usage pattern.

CmRegisterCallbackEx registers a callback for registry operations.
Drivers use this to monitor, filter, or block registry access — commonly
used for self-protection (preventing deletion of driver's own registry keys)
or monitoring (logging all registry changes).
"""
from __future__ import annotations

import struct
from .base import Pattern, PatternMatch


class CmCallbackPattern(Pattern):

    @property
    def name(self) -> str:
        return "cm_callback"

    def scan(self, adapter, callgraph=None, depgraph=None) -> list[PatternMatch]:
        matches: list[PatternMatch] = []

        imports = adapter.imports()
        target_api = None
        target_dll = ""

        for dll, funcs in imports.items():
            for f in funcs:
                if f in ("CmRegisterCallbackEx", "CmRegisterCallback"):
                    target_api = f
                    target_dll = dll
                    break
            if target_api:
                break

        if not target_api:
            return matches

        # Find IAT call sites
        iat_calls = adapter.iat_calls()
        call_sites = [c for c in iat_calls if c["target_func"] == target_api]

        if not call_sites:
            matches.append(PatternMatch(
                pattern_name=self.name,
                confidence=0.5,
                location=0,
                details={
                    "dll": target_dll,
                    "import": target_api,
                    "call_sites": [],
                    "note": "Imported but no direct IAT call site found",
                },
                description=(
                    f"{target_api} is imported but no direct call site was found."
                ),
            ))
            return matches

        text_sec = adapter._find_section(".text")
        raw_data = adapter._raw if text_sec else b""
        is64 = adapter._pe.OPTIONAL_HEADER.Magic == 0x20B

        for site in call_sites:
            rva = site["rva"]
            handler_rva = self._find_callback_function(
                raw_data, text_sec, rva, is64, target_api
            ) if text_sec else None

            details = {
                "dll": target_dll,
                "import": target_api,
                "call_site_rva": f"0x{rva:X}",
                "handler_rva": f"0x{handler_rva:X}" if handler_rva else "unknown",
            }

            confidence = 0.85 if handler_rva else 0.7

            if target_api == "CmRegisterCallbackEx":
                desc = (
                    f"CmRegisterCallbackEx called at RVA 0x{rva:X}. "
                    "Registers an extended registry callback for monitoring/filtering "
                    "registry operations."
                )
            else:
                desc = (
                    f"CmRegisterCallback called at RVA 0x{rva:X}. "
                    "Registers a registry callback (legacy API)."
                )

            if handler_rva:
                desc += f" Callback function at RVA 0x{handler_rva:X}."

            matches.append(PatternMatch(
                pattern_name=self.name,
                confidence=confidence,
                location=rva,
                details=details,
                description=desc,
            ))

        return matches

    @staticmethod
    def _find_callback_function(
        raw_data: bytes,
        text_sec,
        call_rva: int,
        is64: bool,
        api_name: str,
    ) -> int | None:
        """Scan backwards from the call site to find the callback function address.

        For CmRegisterCallbackEx: first argument (RCX) is the callback function.
        Look for LEA RCX, [RIP+disp32] — 48 8D 0D xx xx xx xx
        or MOV RCX, imm64 — 48 B9 xx xx xx xx xx xx xx xx
        """
        if not text_sec or not raw_data:
            return None

        sec_rva = text_sec.VirtualAddress
        raw_offset = text_sec.PointerToRawData

        file_off = call_rva - sec_rva + raw_offset
        search_start = max(raw_offset, file_off - 64)
        region = raw_data[search_start:file_off]

        for i in range(len(region) - 6, -1, -1):
            # LEA RCX, [RIP+disp32]
            if region[i] == 0x48 and region[i + 1] == 0x8D and region[i + 2] == 0x0D:
                disp = struct.unpack_from("<i", region, i + 3)[0]
                lea_rva = (search_start - raw_offset + sec_rva) + i
                target_rva = lea_rva + 7 + disp
                if target_rva > 0:
                    return target_rva

        return None
