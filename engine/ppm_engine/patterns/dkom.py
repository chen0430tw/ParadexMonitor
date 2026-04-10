"""
Detect DKOM (Direct Kernel Object Manipulation) hiding patterns.

DKOM techniques involve directly modifying kernel data structures to hide
processes, drivers, or other objects from the system. Common targets:

    - EPROCESS.ActiveProcessLinks  (unlink process from list)
    - PsLoadedModuleList           (hide driver from module list)
    - MmUnloadedDrivers            (clear unload traces)
    - PiDDBCacheTable              (clean driver database cache)

Detection strategy:
    1. Check for string references to known DKOM targets
    2. Check for MmGetSystemRoutineAddress (dynamic API resolution)
    3. Check for writes to known EPROCESS offsets
    4. Check for PsLoadedModuleList / driver list manipulation strings
"""
from __future__ import annotations

import struct
from .base import Pattern, PatternMatch


# Known EPROCESS offsets by Windows version (x64)
_EPROCESS_OFFSETS = {
    "ActiveProcessLinks": {
        "win10_1507": 0x2E8,
        "win10_1607": 0x2F0,
        "win10_1809": 0x2E8,
        "win10_1903": 0x2F0,
        "win10_2004": 0x448,
        "win10_21H2": 0x448,
        "win11_22H2": 0x448,
    },
    "ImageFileName": {
        "win10_2004": 0x5A8,
        "win10_21H2": 0x5A8,
    },
    "UniqueProcessId": {
        "win10_2004": 0x440,
        "win10_21H2": 0x440,
    },
}

# String indicators of DKOM activity
_DKOM_STRING_INDICATORS = [
    "PsLoadedModuleList",
    "MmUnloadedDrivers",
    "PiDDBCacheTable",
    "MiRememberUnloadedDriver",
    "ActiveProcessLinks",
    "PsInitialSystemProcess",
    "PsActiveProcessHead",
    "NtBuildNumber",
    "KeServiceDescriptorTable",
]

# APIs used for dynamic resolution in DKOM
_RESOLVE_APIS = {
    "MmGetSystemRoutineAddress",
    "RtlFindExportedRoutineByName",
}

# Known ActiveProcessLinks offset values (as little-endian immediates)
_APL_OFFSETS_BYTES = set()
for _versions in _EPROCESS_OFFSETS["ActiveProcessLinks"].values():
    _APL_OFFSETS_BYTES.add(_versions)


class DkomPattern(Pattern):

    @property
    def name(self) -> str:
        return "dkom"

    def scan(self, adapter, callgraph=None, depgraph=None) -> list[PatternMatch]:
        matches: list[PatternMatch] = []

        imports = adapter.imports()
        all_funcs: set[str] = set()
        for funcs in imports.values():
            all_funcs.update(funcs)

        # Stage 1: check for dynamic resolution APIs
        has_dynamic_resolve = bool(all_funcs & _RESOLVE_APIS)

        # Stage 2: check strings for DKOM indicators
        strings_list = adapter.strings(min_len=4)
        dkom_strings: list[str] = []
        for s in strings_list:
            val = s.get("value", "")
            for indicator in _DKOM_STRING_INDICATORS:
                if indicator in val:
                    dkom_strings.append(val)
                    break

        # Stage 3: scan .text for writes to known EPROCESS offsets
        offset_hits = self._scan_for_offset_writes(adapter)

        # Evaluate findings
        if not dkom_strings and not offset_hits and not has_dynamic_resolve:
            return matches

        # Calculate confidence
        confidence = 0.0
        indicators: list[str] = []

        if dkom_strings:
            # Strings referencing kernel structures used in DKOM
            confidence += 0.3
            indicators.append(
                f"References to DKOM targets: {', '.join(set(dkom_strings)[:5])}"
            )

        if has_dynamic_resolve:
            confidence += 0.2
            indicators.append(
                "Uses MmGetSystemRoutineAddress for dynamic API resolution"
            )

        if offset_hits:
            confidence += 0.4
            for hit in offset_hits:
                indicators.append(
                    f"Writes to EPROCESS offset 0x{hit['offset']:X} at RVA 0x{hit['rva']:X} "
                    f"(possible {hit['field']} manipulation)"
                )

        # Process hiding: ActiveProcessLinks + PsInitialSystemProcess
        has_apl = any("ActiveProcessLinks" in s for s in dkom_strings)
        has_ps_initial = any("PsInitialSystemProcess" in s for s in dkom_strings)
        if has_apl or has_ps_initial:
            confidence += 0.1
            indicators.append("Strong DKOM indicator: ActiveProcessLinks/PsInitialSystemProcess reference")

        # Driver hiding: PsLoadedModuleList
        has_module_list = any("PsLoadedModuleList" in s for s in dkom_strings)
        has_unloaded = any("MmUnloadedDrivers" in s for s in dkom_strings)
        has_piddb = any("PiDDBCacheTable" in s for s in dkom_strings)

        if has_module_list:
            indicators.append("PsLoadedModuleList access — may hide from driver enumeration")
        if has_unloaded:
            indicators.append("MmUnloadedDrivers access — may erase unload evidence")
        if has_piddb:
            indicators.append("PiDDBCacheTable access — may clean driver database cache")

        confidence = round(min(confidence, 1.0), 2)

        # Only report if there's meaningful evidence
        if confidence < 0.2:
            return matches

        location = offset_hits[0]["rva"] if offset_hits else 0

        desc_parts = [f"DKOM pattern detected (confidence: {confidence})."]
        if has_apl or offset_hits:
            desc_parts.append("Process hiding capability via ActiveProcessLinks manipulation.")
        if has_module_list or has_unloaded or has_piddb:
            desc_parts.append("Driver hiding capability via module list manipulation.")
        if has_dynamic_resolve and not dkom_strings and not offset_hits:
            desc_parts.append(
                "Dynamic API resolution present — potential DKOM preparation "
                "(no direct evidence of structure manipulation found)."
            )

        matches.append(PatternMatch(
            pattern_name=self.name,
            confidence=confidence,
            location=location,
            details={
                "dkom_strings": list(set(dkom_strings)),
                "offset_writes": offset_hits,
                "has_dynamic_resolve": has_dynamic_resolve,
                "indicators": indicators,
            },
            description=" ".join(desc_parts),
        ))

        return matches

    @staticmethod
    def _scan_for_offset_writes(adapter) -> list[dict]:
        """Scan .text section for instructions that reference known EPROCESS offsets.

        Look for patterns like:
            mov [reg + 0x448], ...    (write to ActiveProcessLinks)
            lea reg, [reg + 0x448]    (compute address of ActiveProcessLinks)
        """
        text_sec = adapter._find_section(".text")
        if not text_sec:
            return []

        raw_offset = text_sec.PointerToRawData
        raw_size = text_sec.SizeOfRawData
        sec_rva = text_sec.VirtualAddress
        data = adapter._raw[raw_offset: raw_offset + raw_size]

        hits: list[dict] = []

        # Collect all interesting offsets
        target_offsets: dict[int, str] = {}
        for field_name, versions in _EPROCESS_OFFSETS.items():
            for ver, offset in versions.items():
                target_offsets[offset] = field_name

        # Scan for MOV/LEA with disp32 matching known offsets
        # Common encodings with disp32:
        #   MOV [reg + disp32], reg:  89 xx xx xx xx xx  (ModRM + SIB + disp32)
        #   LEA reg, [reg + disp32]:  48 8D xx xx xx xx xx
        i = 0
        while i < len(data) - 5:
            # Check for 4-byte displacement that matches known offsets
            # Look for disp32 in instructions by checking all 4-byte windows
            if i + 3 < len(data):
                disp = struct.unpack_from("<i", data, i)[0]
                if disp in target_offsets and 0 < disp < 0x1000:
                    # Verify this looks like part of an instruction (not random data)
                    # Check preceding bytes for common instruction prefixes/opcodes
                    if i >= 2:
                        prev2 = data[i - 2]
                        prev1 = data[i - 1]
                        # REX prefix (0x40-0x4F) + opcode
                        is_likely_insn = (
                            (0x40 <= prev2 <= 0x4F) or  # REX prefix
                            prev2 in (0x89, 0x8B, 0x8D, 0x48, 0x4C) or  # MOV/LEA
                            prev1 in (0x80, 0x81, 0x83, 0x88, 0x89, 0x8A, 0x8B, 0x8D)
                        )
                        if is_likely_insn:
                            rva = sec_rva + i - 2
                            hits.append({
                                "rva": rva,
                                "offset": disp,
                                "field": target_offsets[disp],
                            })
            i += 1

        # Deduplicate hits at the same RVA
        seen_rvas: set[int] = set()
        unique: list[dict] = []
        for h in hits:
            if h["rva"] not in seen_rvas:
                seen_rvas.add(h["rva"])
                unique.append(h)

        return unique[:20]  # Cap at 20 to avoid noise
