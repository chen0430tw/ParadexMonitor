"""
Detect handle access stripping pattern.

Anti-cheat and protection drivers use ObRegisterCallbacks to register
a PreOperation callback that strips dangerous access rights from handles
being opened to protected processes. The typical pattern in the callback:

    if (target_pid == protected_pid) {
        OperationInfo->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_ALL_ACCESS;
        // or: DesiredAccess &= PROCESS_QUERY_LIMITED_INFORMATION;
    }

Detection:
    1. Find ObRegisterCallbacks call site
    2. Identify the callback handler
    3. Look for AND instruction that masks DesiredAccess
"""
from __future__ import annotations

import struct
from .base import Pattern, PatternMatch


# Common access masks used in handle stripping
_ACCESS_MASKS = {
    0x1000: "PROCESS_QUERY_LIMITED_INFORMATION",
    0x0400: "PROCESS_QUERY_INFORMATION",
    0x1FFFFF: "PROCESS_ALL_ACCESS",
    0x001F0FFF: "PROCESS_ALL_ACCESS (legacy)",
    0x1F03FF: "THREAD_ALL_ACCESS",
    0x0200: "PROCESS_VM_READ",
    0x0010: "PROCESS_VM_WRITE",
    0x0020: "PROCESS_VM_OPERATION",
    0x0008: "PROCESS_SUSPEND_RESUME",
    0x0001: "PROCESS_TERMINATE",
    0x0002: "PROCESS_CREATE_THREAD",
}

# Masks that strip dangerous access (keep only safe bits)
_STRIP_MASKS = {
    0x1000,   # PROCESS_QUERY_LIMITED_INFORMATION only
    0x0400,   # PROCESS_QUERY_INFORMATION only
    0x1400,   # QUERY + QUERY_LIMITED
    0x0000,   # Strip everything
}

# Masks that remove specific rights (AND NOT patterns)
_STRIP_NOT_MASKS = {
    0x1FFFFF,       # ~PROCESS_ALL_ACCESS
    0x001F0FFF,     # ~PROCESS_ALL_ACCESS (legacy)
    0x0001,         # ~PROCESS_TERMINATE
    0x0010,         # ~PROCESS_VM_WRITE
    0x0020,         # ~PROCESS_VM_OPERATION
    0x0002,         # ~PROCESS_CREATE_THREAD
}


class HandleStripPattern(Pattern):

    @property
    def name(self) -> str:
        return "handle_strip"

    def scan(self, adapter, callgraph=None, depgraph=None) -> list[PatternMatch]:
        matches: list[PatternMatch] = []

        imports = adapter.imports()
        all_funcs: set[str] = set()
        for funcs in imports.values():
            all_funcs.update(funcs)

        # Must have ObRegisterCallbacks
        if "ObRegisterCallbacks" not in all_funcs:
            return matches

        # Scan .text for AND instructions with access mask immediates
        text_sec = adapter._find_section(".text")
        if not text_sec:
            return matches

        raw_offset = text_sec.PointerToRawData
        raw_size = text_sec.SizeOfRawData
        sec_rva = text_sec.VirtualAddress
        data = adapter._raw[raw_offset: raw_offset + raw_size]

        and_hits = self._find_and_instructions(data, sec_rva)

        if not and_hits:
            # ObRegisterCallbacks present but no AND with access masks found
            # Could still be stripping via assignment (mov) rather than AND
            mov_hits = self._find_mov_access_assign(data, sec_rva)
            if mov_hits:
                for hit in mov_hits:
                    mask_val = hit["value"]
                    mask_name = _ACCESS_MASKS.get(mask_val, f"0x{mask_val:X}")
                    matches.append(PatternMatch(
                        pattern_name=self.name,
                        confidence=0.6,
                        location=hit["rva"],
                        details={
                            "type": "assignment",
                            "rva": f"0x{hit['rva']:X}",
                            "value": f"0x{mask_val:X}",
                            "mask_name": mask_name,
                        },
                        description=(
                            f"Possible handle access override at RVA 0x{hit['rva']:X}. "
                            f"Assigns DesiredAccess = {mask_name} (0x{mask_val:X}). "
                            "Combined with ObRegisterCallbacks import, this likely strips "
                            "handle access rights."
                        ),
                    ))
            return matches

        # Process AND hits
        for hit in and_hits:
            mask_val = hit["mask"]
            is_strip = mask_val in _STRIP_MASKS
            is_not_strip = mask_val in _STRIP_NOT_MASKS

            if is_strip:
                mask_name = _ACCESS_MASKS.get(mask_val, f"0x{mask_val:X}")
                confidence = 0.85
                desc = (
                    f"Handle access stripping at RVA 0x{hit['rva']:X}. "
                    f"AND with {mask_name} (0x{mask_val:X}) — keeps only safe access rights."
                )
            elif is_not_strip:
                mask_name = _ACCESS_MASKS.get(mask_val, f"0x{mask_val:X}")
                confidence = 0.7
                desc = (
                    f"Possible handle access stripping at RVA 0x{hit['rva']:X}. "
                    f"AND with complement of {mask_name}. "
                    "May be removing specific dangerous access rights."
                )
            else:
                mask_name = _ACCESS_MASKS.get(mask_val, f"0x{mask_val:X}")
                confidence = 0.5
                desc = (
                    f"AND instruction with access-mask-like value at RVA 0x{hit['rva']:X}. "
                    f"Mask: 0x{mask_val:X} ({mask_name}). "
                    "May be related to handle access filtering."
                )

            matches.append(PatternMatch(
                pattern_name=self.name,
                confidence=confidence,
                location=hit["rva"],
                details={
                    "type": "and_mask",
                    "rva": f"0x{hit['rva']:X}",
                    "mask": f"0x{mask_val:X}",
                    "mask_name": mask_name,
                    "is_strip": is_strip,
                    "encoding": hit.get("encoding", ""),
                },
                description=desc,
            ))

        return matches

    @staticmethod
    def _find_and_instructions(data: bytes, sec_rva: int) -> list[dict]:
        """Scan for AND [reg+offset], imm32 instructions with access mask values.

        Common encodings:
            81 /4 id    — AND r/m32, imm32
            83 /4 ib    — AND r/m32, imm8 (sign-extended)
            21 /r       — AND r/m32, r32
        With REX.W prefix (48) for 64-bit operands.
        """
        hits: list[dict] = []
        target_masks = _STRIP_MASKS | _STRIP_NOT_MASKS | set(_ACCESS_MASKS.keys())

        i = 0
        while i < len(data) - 5:
            # AND r/m, imm32: 81 E? xx xx xx xx (register direct)
            # or: 81 6? xx xx xx xx xx (with modrm displacement)
            if data[i] == 0x81:
                modrm = data[i + 1]
                reg_field = (modrm >> 3) & 7
                if reg_field == 4:  # /4 = AND
                    mod = (modrm >> 6) & 3
                    if mod == 3:
                        # Register direct: AND reg, imm32
                        if i + 5 < len(data):
                            imm = struct.unpack_from("<I", data, i + 2)[0]
                            if imm in target_masks:
                                hits.append({
                                    "rva": sec_rva + i,
                                    "mask": imm,
                                    "encoding": f"81 {data[i+1]:02X} {imm:08X}",
                                })
                        i += 6
                        continue
                    elif mod == 1:
                        # [reg + disp8] + imm32
                        if i + 7 < len(data):
                            imm = struct.unpack_from("<I", data, i + 3)[0]
                            if imm in target_masks:
                                hits.append({
                                    "rva": sec_rva + i,
                                    "mask": imm,
                                    "encoding": f"81 {data[i+1]:02X} disp8 {imm:08X}",
                                })
                        i += 7
                        continue
                    elif mod == 2:
                        # [reg + disp32] + imm32
                        if i + 10 < len(data):
                            imm = struct.unpack_from("<I", data, i + 6)[0]
                            if imm in target_masks:
                                hits.append({
                                    "rva": sec_rva + i,
                                    "mask": imm,
                                    "encoding": f"81 {data[i+1]:02X} disp32 {imm:08X}",
                                })
                        i += 10
                        continue

            # Check for REX.W prefix + AND
            if data[i] == 0x48 and i + 1 < len(data) and data[i + 1] == 0x81:
                modrm = data[i + 2] if i + 2 < len(data) else 0
                reg_field = (modrm >> 3) & 7
                if reg_field == 4:
                    mod = (modrm >> 6) & 3
                    if mod == 3 and i + 6 < len(data):
                        imm = struct.unpack_from("<I", data, i + 3)[0]
                        if imm in target_masks:
                            hits.append({
                                "rva": sec_rva + i,
                                "mask": imm,
                                "encoding": f"48 81 {modrm:02X} {imm:08X}",
                            })
                        i += 7
                        continue
                    elif mod == 1 and i + 8 < len(data):
                        imm = struct.unpack_from("<I", data, i + 4)[0]
                        if imm in target_masks:
                            hits.append({
                                "rva": sec_rva + i,
                                "mask": imm,
                                "encoding": f"48 81 {modrm:02X} disp8 {imm:08X}",
                            })
                        i += 8
                        continue

            i += 1

        return hits[:20]

    @staticmethod
    def _find_mov_access_assign(data: bytes, sec_rva: int) -> list[dict]:
        """Find MOV [reg+offset], imm32 where imm32 is a known safe access mask.

        Some drivers assign DesiredAccess directly rather than AND-masking.
        """
        hits: list[dict] = []
        safe_values = {0x1000, 0x0400, 0x1400, 0x0000}

        i = 0
        while i < len(data) - 7:
            # C7 /0 id — MOV r/m32, imm32
            if data[i] == 0xC7:
                modrm = data[i + 1]
                reg_field = (modrm >> 3) & 7
                if reg_field == 0:
                    mod = (modrm >> 6) & 3
                    if mod == 1 and i + 7 < len(data):
                        # [reg + disp8], imm32
                        imm = struct.unpack_from("<I", data, i + 3)[0]
                        if imm in safe_values:
                            hits.append({
                                "rva": sec_rva + i,
                                "value": imm,
                            })
                    elif mod == 2 and i + 10 < len(data):
                        # [reg + disp32], imm32
                        imm = struct.unpack_from("<I", data, i + 6)[0]
                        if imm in safe_values:
                            hits.append({
                                "rva": sec_rva + i,
                                "value": imm,
                            })
            i += 1

        return hits[:10]
