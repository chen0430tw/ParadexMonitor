"""
Mach-O adapter -- extract structured info from macOS/iOS binaries using lief.

Mirrors the PEAdapter/ELFAdapter interface so the pipeline can handle
Mach-O executables, dylibs, bundles, and kernel extensions (.kext).
"""
from __future__ import annotations

import re
from typing import Optional

try:
    import lief
except ImportError:
    lief = None  # type: ignore[assignment]


class MachOAdapter:
    """Parse a Mach-O binary and expose imports, exports, sections, strings."""

    def __init__(self, path: str) -> None:
        if lief is None:
            raise RuntimeError("lief is required: pip install lief")
        self.path = path
        # lief.parse for Mach-O returns a FatBinary or Binary
        parsed = lief.parse(path)
        if parsed is None:
            raise ValueError(f"lief could not parse: {path}")
        # Handle fat binaries -- pick the first slice
        if isinstance(parsed, lief.MachO.FatBinary):
            self._bin = parsed.at(0)
        else:
            self._bin = parsed
        with open(path, "rb") as f:
            self._raw = f.read()

    # ------------------------------------------------------------------
    # imports
    # ------------------------------------------------------------------
    def imports(self) -> dict[str, list[str]]:
        """Return library -> [symbol, ...] mapping.

        Uses dyld binding info to resolve which library provides each symbol.
        Falls back to imported_symbols if binding info is unavailable.
        """
        result: dict[str, list[str]] = {}

        # Try dyld bindings first (most reliable for library resolution)
        seen: set[str] = set()
        try:
            if self._bin.has_dyld_info:
                for bd in self._bin.dyld_info.bindings:
                    sym_name = bd.symbol.name if bd.symbol else ""
                    lib_name = bd.library.name if bd.library else ""
                    if sym_name and sym_name not in seen:
                        seen.add(sym_name)
                        # Strip leading underscore (Mach-O convention)
                        clean = sym_name.lstrip("_") if sym_name.startswith("_") else sym_name
                        lib_short = lib_name.rsplit("/", 1)[-1] if lib_name else "(unresolved)"
                        result.setdefault(lib_short, []).append(clean)
        except Exception:
            pass

        # Try chained fixups (newer Mach-O format)
        if not result:
            try:
                if hasattr(self._bin, "dyld_chained_fixups") and self._bin.dyld_chained_fixups:
                    for fx in self._bin.dyld_chained_fixups.bindings:
                        sym_name = fx.symbol.name if hasattr(fx, "symbol") and fx.symbol else ""
                        lib_name = fx.library.name if hasattr(fx, "library") and fx.library else ""
                        if sym_name and sym_name not in seen:
                            seen.add(sym_name)
                            clean = sym_name.lstrip("_") if sym_name.startswith("_") else sym_name
                            lib_short = lib_name.rsplit("/", 1)[-1] if lib_name else "(unresolved)"
                            result.setdefault(lib_short, []).append(clean)
            except Exception:
                pass

        # Fallback: imported_symbols without library resolution
        if not result:
            for sym in self._bin.imported_symbols:
                name = sym.name
                if name and name not in seen:
                    seen.add(name)
                    clean = name.lstrip("_") if name.startswith("_") else name
                    result.setdefault("(unresolved)", []).append(clean)

        return result

    # ------------------------------------------------------------------
    # exports
    # ------------------------------------------------------------------
    def exports(self) -> list[str]:
        """Return exported symbol names."""
        return [s.name.lstrip("_") for s in self._bin.exported_symbols if s.name]

    # ------------------------------------------------------------------
    # sections
    # ------------------------------------------------------------------
    def sections(self) -> list[dict]:
        """Return section metadata: segment, name, va, size, entropy."""
        out: list[dict] = []
        for sec in self._bin.sections:
            entropy = sec.entropy if hasattr(sec, "entropy") else 0.0
            out.append({
                "name": f"{sec.segment_name},{sec.name}",
                "va": sec.virtual_address,
                "size": sec.size,
                "offset": sec.offset,
                "entropy": round(entropy, 4),
                "segment": sec.segment_name,
            })
        return out

    # ------------------------------------------------------------------
    # entry_point
    # ------------------------------------------------------------------
    def entry_point(self) -> int:
        """Return the entry point virtual address."""
        return self._bin.entrypoint

    # ------------------------------------------------------------------
    # strings
    # ------------------------------------------------------------------
    def strings(self, min_len: int = 6) -> list[dict]:
        """Extract strings from __cstring section and raw ASCII scan."""
        results: list[dict] = []

        # First: extract from __cstring section (reliable, with correct RVAs)
        for sec in self._bin.sections:
            if sec.name == "__cstring":
                offset = sec.offset
                data = self._raw[offset:offset + sec.size]
                for part in data.split(b"\x00"):
                    if len(part) >= min_len:
                        try:
                            val = part.decode("ascii")
                            rva = sec.virtual_address + (self._raw.index(part, offset) - offset)
                            results.append({"rva": rva, "encoding": "ascii", "value": val})
                        except (UnicodeDecodeError, ValueError):
                            pass
                break

        # Fallback: raw ASCII scan if __cstring didn't yield much
        if len(results) < 10:
            pattern = re.compile(rb"[\x20-\x7e]{%d,}" % min_len)
            seen = {r["value"] for r in results}
            for m in pattern.finditer(self._raw):
                val = m.group().decode("ascii", errors="replace")
                if val not in seen:
                    seen.add(val)
                    results.append({"rva": m.start(), "encoding": "ascii", "value": val})

        return results

    # ------------------------------------------------------------------
    # iat_calls (stub calls)
    # ------------------------------------------------------------------
    def iat_calls(self) -> list[dict]:
        """Find stub call sites in __text section.

        Mach-O uses __stubs for dynamic calls, analogous to IAT/PLT.
        We scan __text for branch instructions targeting the __stubs section.
        """
        results: list[dict] = []
        text_sec = None
        stubs_sec = None
        for sec in self._bin.sections:
            if sec.name == "__text":
                text_sec = sec
            elif sec.name == "__stubs":
                stubs_sec = sec

        if text_sec is None or stubs_sec is None:
            return results

        stubs_start = stubs_sec.virtual_address
        stubs_end = stubs_start + stubs_sec.size

        # Build stub index -> symbol name mapping via indirect symbol table.
        # lief's indirect_symbols API may not be available, so read raw data.
        import struct as _struct
        stub_symbols: dict[int, str] = {}
        cpu = self._bin.header.cpu_type
        entry_size = 12 if "ARM" in str(cpu) else 6
        reserved1 = stubs_sec.reserved1 if hasattr(stubs_sec, "reserved1") else 0

        try:
            all_syms = list(self._bin.symbols)
            # Find LC_DYSYMTAB to get indirect symbol table offset
            isym_off = 0
            n_isym = 0
            for cmd in self._bin.commands:
                if cmd.command == lief.MachO.LoadCommand.TYPE.DYSYMTAB:
                    data = bytes(cmd.data)
                    if len(data) >= 64:
                        isym_off = _struct.unpack_from("<I", data, 56)[0]
                        n_isym = _struct.unpack_from("<I", data, 60)[0]
                    break

            if isym_off and n_isym:
                n_stubs = stubs_sec.size // entry_size
                for i in range(min(n_stubs, n_isym - reserved1)):
                    raw_idx = _struct.unpack_from("<I", self._raw, isym_off + (reserved1 + i) * 4)[0]
                    if raw_idx < len(all_syms):
                        name = all_syms[raw_idx].name
                        name = name.lstrip("_") if name.startswith("_") else name
                        addr = stubs_start + i * entry_size
                        stub_symbols[addr] = name
        except Exception:
            pass

        # Scan __text for calls/branches to __stubs
        text_data = self._raw[text_sec.offset:text_sec.offset + text_sec.size]
        text_va = text_sec.virtual_address
        cpu = self._bin.header.cpu_type

        if "ARM" in str(cpu):
            # ARM64: BL instruction = 0x94xxxxxx (bits 31:26 = 100101)
            i = 0
            while i < len(text_data) - 3:
                insn = int.from_bytes(text_data[i:i + 4], "little")
                if (insn >> 26) == 0x25:  # BL
                    imm26 = insn & 0x3FFFFFF
                    if imm26 & 0x2000000:  # sign extend
                        imm26 |= ~0x3FFFFFF
                    target = text_va + i + (imm26 << 2)
                    if stubs_start <= target < stubs_end:
                        func_name = stub_symbols.get(target, f"stub_{target:#x}")
                        results.append({
                            "rva": text_va + i,
                            "target_dll": "",
                            "target_func": func_name,
                        })
                i += 4
        else:
            # x86-64: E8 rel32 (call)
            i = 0
            while i < len(text_data) - 4:
                if text_data[i] == 0xE8:
                    rel32 = int.from_bytes(text_data[i + 1:i + 5], "little", signed=True)
                    target = text_va + i + 5 + rel32
                    if stubs_start <= target < stubs_end:
                        func_name = stub_symbols.get(target, f"stub_{target:#x}")
                        results.append({
                            "rva": text_va + i,
                            "target_dll": "",
                            "target_func": func_name,
                        })
                i += 1

        return results

    # ------------------------------------------------------------------
    # is_driver / is_kernel_extension
    # ------------------------------------------------------------------
    def is_driver(self) -> bool:
        """Check if this is a kernel extension (.kext)."""
        return self.is_kernel_extension()

    def is_kernel_extension(self) -> bool:
        """Heuristic: check for kext indicators."""
        # Check for com.apple.kpi.* library dependencies
        for lib in self._bin.libraries:
            if "com.apple.kpi" in lib.name:
                return True

        # Check file type (KEXT_BUNDLE = 0xB)
        try:
            if int(self._bin.header.file_type) == 0xB:
                return True
        except Exception:
            pass

        return False
