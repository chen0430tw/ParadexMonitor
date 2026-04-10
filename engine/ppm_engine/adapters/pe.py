"""
PE (Portable Executable) adapter — extract structured info for the topology builder.

Primary backend: pefile (required).
Optional backend: lief (for richer analysis when available).
"""
from __future__ import annotations

import math
import struct
from pathlib import Path
from typing import Optional

try:
    import pefile
except ImportError:
    pefile = None  # type: ignore[assignment]

try:
    import lief
except ImportError:
    lief = None  # type: ignore[assignment]


class PEAdapter:
    """Parse a PE file and expose imports, exports, sections, strings, and IAT calls."""

    def __init__(self, path: str) -> None:
        if pefile is None:
            raise RuntimeError("pefile is required: pip install pefile")
        self.path = path
        self._pe = pefile.PE(path)
        self._data: Optional[bytes] = None

    # ------------------------------------------------------------------
    # lazy raw bytes
    # ------------------------------------------------------------------
    @property
    def _raw(self) -> bytes:
        if self._data is None:
            self._data = Path(self.path).read_bytes()
        return self._data

    # ------------------------------------------------------------------
    # imports
    # ------------------------------------------------------------------
    def imports(self) -> dict[str, list[str]]:
        """Return DLL -> [function, ...] mapping from the import directory."""
        self._pe.parse_data_directories(
            directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]]
        )
        result: dict[str, list[str]] = {}
        if not hasattr(self._pe, "DIRECTORY_ENTRY_IMPORT"):
            return result
        for entry in self._pe.DIRECTORY_ENTRY_IMPORT:
            dll = entry.dll.decode("ascii", errors="replace")
            funcs: list[str] = []
            for imp in entry.imports:
                name = imp.name.decode("ascii", errors="replace") if imp.name else f"ord#{imp.ordinal}"
                funcs.append(name)
            result[dll] = funcs
        return result

    # ------------------------------------------------------------------
    # exports
    # ------------------------------------------------------------------
    def exports(self) -> list[str]:
        """Return list of exported symbol names."""
        self._pe.parse_data_directories(
            directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]]
        )
        if not hasattr(self._pe, "DIRECTORY_ENTRY_EXPORT"):
            return []
        syms: list[str] = []
        for exp in self._pe.DIRECTORY_ENTRY_EXPORT.symbols:
            name = exp.name.decode("ascii", errors="replace") if exp.name else f"ord#{exp.ordinal}"
            syms.append(name)
        return syms

    # ------------------------------------------------------------------
    # sections
    # ------------------------------------------------------------------
    def sections(self) -> list[dict]:
        """Return section metadata: name, va, size, entropy, characteristics."""
        out: list[dict] = []
        for sec in self._pe.sections:
            name = sec.Name.rstrip(b"\x00").decode("ascii", errors="replace")
            out.append({
                "name": name,
                "va": sec.VirtualAddress,
                "size": sec.Misc_VirtualSize,
                "raw_size": sec.SizeOfRawData,
                "entropy": round(sec.get_entropy(), 4),
                "characteristics": sec.Characteristics,
            })
        return out

    # ------------------------------------------------------------------
    # entry point
    # ------------------------------------------------------------------
    def entry_point(self) -> int:
        """Return the entry point RVA."""
        return self._pe.OPTIONAL_HEADER.AddressOfEntryPoint

    # ------------------------------------------------------------------
    # IAT calls  (FF 15 disp32 — call [rip+disp32] on x64)
    # ------------------------------------------------------------------
    def iat_calls(self) -> list[dict]:
        """Scan .text for FF 15 (indirect call through IAT) and resolve targets."""
        # Build IAT RVA -> (dll, func) lookup
        iat_map = self._build_iat_map()
        if not iat_map:
            return []

        text_sec = self._find_section(".text")
        if text_sec is None:
            return []

        is64 = self._pe.OPTIONAL_HEADER.Magic == 0x20B
        raw_offset = text_sec.PointerToRawData
        raw_size = text_sec.SizeOfRawData
        sec_rva = text_sec.VirtualAddress
        data = self._raw[raw_offset : raw_offset + raw_size]

        results: list[dict] = []
        i = 0
        while i < len(data) - 5:
            # FF 15 xx xx xx xx
            if data[i] == 0xFF and data[i + 1] == 0x15:
                disp = struct.unpack_from("<i", data, i + 2)[0]
                instr_rva = sec_rva + i
                if is64:
                    # RIP-relative: target = RVA_of_next_instr + disp
                    target_rva = instr_rva + 6 + disp
                else:
                    # Absolute VA in 32-bit — disp is the VA of the IAT slot
                    target_rva = disp - self._pe.OPTIONAL_HEADER.ImageBase
                if target_rva in iat_map:
                    dll, func = iat_map[target_rva]
                    results.append({
                        "rva": instr_rva,
                        "target_dll": dll,
                        "target_func": func,
                    })
                i += 6
            else:
                i += 1
        return results

    # ------------------------------------------------------------------
    # strings
    # ------------------------------------------------------------------
    def strings(self, min_len: int = 6) -> list[dict]:
        """Extract ASCII and UTF-16LE strings with their file-offset RVA."""
        results: list[dict] = []
        raw = self._raw

        # ASCII
        results.extend(self._extract_ascii(raw, min_len))
        # UTF-16LE
        results.extend(self._extract_utf16(raw, min_len))

        results.sort(key=lambda s: s["rva"])
        return results

    # ------------------------------------------------------------------
    # is_driver
    # ------------------------------------------------------------------
    def is_driver(self) -> bool:
        """True if subsystem is IMAGE_SUBSYSTEM_NATIVE (kernel driver)."""
        return self._pe.OPTIONAL_HEADER.Subsystem == 1

    # ------------------------------------------------------------------
    # helpers
    # ------------------------------------------------------------------
    def _build_iat_map(self) -> dict[int, tuple[str, str]]:
        """Build mapping: IAT slot RVA -> (dll_name, func_name)."""
        self._pe.parse_data_directories(
            directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]]
        )
        m: dict[int, tuple[str, str]] = {}
        if not hasattr(self._pe, "DIRECTORY_ENTRY_IMPORT"):
            return m
        for entry in self._pe.DIRECTORY_ENTRY_IMPORT:
            dll = entry.dll.decode("ascii", errors="replace")
            for imp in entry.imports:
                if imp.address:
                    rva = imp.address - self._pe.OPTIONAL_HEADER.ImageBase
                    name = imp.name.decode("ascii", errors="replace") if imp.name else f"ord#{imp.ordinal}"
                    m[rva] = (dll, name)
        return m

    def _find_section(self, name: str) -> Optional[object]:
        for sec in self._pe.sections:
            sec_name = sec.Name.rstrip(b"\x00").decode("ascii", errors="replace")
            if sec_name == name:
                return sec
        return None

    @staticmethod
    def _extract_ascii(data: bytes, min_len: int) -> list[dict]:
        results: list[dict] = []
        start = -1
        for i, b in enumerate(data):
            if 0x20 <= b <= 0x7E:
                if start < 0:
                    start = i
            else:
                if start >= 0 and (i - start) >= min_len:
                    results.append({
                        "rva": start,
                        "encoding": "ascii",
                        "value": data[start:i].decode("ascii"),
                    })
                start = -1
        # trailing
        if start >= 0 and (len(data) - start) >= min_len:
            results.append({
                "rva": start,
                "encoding": "ascii",
                "value": data[start:].decode("ascii"),
            })
        return results

    @staticmethod
    def _extract_utf16(data: bytes, min_len: int) -> list[dict]:
        results: list[dict] = []
        start = -1
        i = 0
        while i < len(data) - 1:
            lo, hi = data[i], data[i + 1]
            if hi == 0 and 0x20 <= lo <= 0x7E:
                if start < 0:
                    start = i
                i += 2
            else:
                if start >= 0:
                    char_count = (i - start) // 2
                    if char_count >= min_len:
                        try:
                            value = data[start:i].decode("utf-16-le")
                            results.append({
                                "rva": start,
                                "encoding": "utf-16-le",
                                "value": value,
                            })
                        except UnicodeDecodeError:
                            pass
                start = -1
                i += 2
        # trailing
        if start >= 0:
            char_count = (len(data) - start) // 2
            if char_count >= min_len:
                try:
                    value = data[start : start + char_count * 2].decode("utf-16-le")
                    results.append({
                        "rva": start,
                        "encoding": "utf-16-le",
                        "value": value,
                    })
                except UnicodeDecodeError:
                    pass
        return results

    def close(self) -> None:
        self._pe.close()

    def __enter__(self) -> "PEAdapter":
        return self

    def __exit__(self, *exc) -> None:
        self.close()
