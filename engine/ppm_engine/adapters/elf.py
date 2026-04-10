"""
ELF adapter -- extract structured info from ELF binaries using lief.

Mirrors the PEAdapter interface so the rest of the pipeline
(callgraph, depgraph, patterns) can treat ELF and PE identically.
"""
from __future__ import annotations

import re
from typing import Optional

try:
    import lief
except ImportError:
    lief = None  # type: ignore[assignment]


class ELFAdapter:
    """Parse an ELF file and expose imports, exports, sections, and metadata."""

    def __init__(self, path: str) -> None:
        if lief is None:
            raise RuntimeError("lief is required: pip install lief")
        self.path = path
        self._bin: lief.ELF.Binary = lief.parse(path)
        if self._bin is None:
            raise ValueError(f"lief could not parse: {path}")
        with open(path, "rb") as f:
            self._raw = f.read()

    # ------------------------------------------------------------------
    # imports  (dynamic symbols that are imported / undefined)
    # ------------------------------------------------------------------
    def imports(self) -> dict[str, list[str]]:
        """Return library -> [symbol, ...] mapping from the dynamic section.

        lief groups imported symbols by the library that provides them
        (via DT_NEEDED entries and symbol versioning).  When the providing
        library cannot be determined, symbols go under the key ''.
        """
        result: dict[str, list[str]] = {}

        # Collect DT_NEEDED library names
        needed: list[str] = []
        try:
            for entry in self._bin.dynamic_entries:
                if entry.tag == lief.ELF.DynamicEntry.TAG.NEEDED:
                    needed.append(entry.name)
        except Exception:
            pass

        # Map symbols by their version library (best-effort)
        sym_lib_map: dict[str, str] = {}
        try:
            for req in self._bin.symbols_version_requirement:
                lib = req.name
                aux_list = getattr(req, "get_auxiliary_symbols", getattr(req, "auxiliary_symbols", None))
                if callable(aux_list):
                    aux_list = aux_list()
                if aux_list:
                    for aux in aux_list:
                        sym_lib_map[aux.name] = lib
        except Exception:
            pass

        for sym in self._bin.imported_symbols:
            name = sym.name
            if not name:
                continue
            # Try to resolve library via version info
            lib = ""
            if hasattr(sym, "symbol_version") and sym.symbol_version:
                sv = sym.symbol_version
                if hasattr(sv, "symbol_version_auxiliary") and sv.symbol_version_auxiliary:
                    aux_name = sv.symbol_version_auxiliary.name
                    lib = sym_lib_map.get(aux_name, "")
            result.setdefault(lib, []).append(name)

        # If we couldn't resolve any libraries, just group all under first NEEDED
        if list(result.keys()) == [""] and needed:
            result = {needed[0]: result.pop("")}

        return result

    # ------------------------------------------------------------------
    # exports
    # ------------------------------------------------------------------
    def exports(self) -> list[str]:
        """Return list of exported symbol names."""
        return [s.name for s in self._bin.exported_symbols if s.name]

    # ------------------------------------------------------------------
    # sections
    # ------------------------------------------------------------------
    def sections(self) -> list[dict]:
        """Return section metadata: name, va, size, entropy, type."""
        out: list[dict] = []
        for sec in self._bin.sections:
            entropy = sec.entropy if hasattr(sec, "entropy") else 0.0
            out.append({
                "name": sec.name,
                "va": sec.virtual_address,
                "size": sec.size,
                "offset": sec.offset,
                "entropy": round(entropy, 4),
                "type": str(sec.type).split(".")[-1] if sec.type else "UNKNOWN",
            })
        return out

    # ------------------------------------------------------------------
    # entry point
    # ------------------------------------------------------------------
    def entry_point(self) -> int:
        """Return the entry point virtual address."""
        return self._bin.entrypoint

    # ------------------------------------------------------------------
    # strings
    # ------------------------------------------------------------------
    def strings(self, min_len: int = 6) -> list[dict]:
        """Extract printable ASCII strings from the binary."""
        results: list[dict] = []
        pattern = re.compile(rb"[\x20-\x7e]{%d,}" % min_len)
        for m in pattern.finditer(self._raw):
            results.append({
                "rva": m.start(),
                "encoding": "ascii",
                "value": m.group().decode("ascii", errors="replace"),
            })
        return results

    # ------------------------------------------------------------------
    # iat_calls  (PLT call sites for ELF -- equivalent of IAT for PE)
    # ------------------------------------------------------------------
    def iat_calls(self) -> list[dict]:
        """Find PLT call sites in .text section.

        ELF uses the PLT/PLT.sec for dynamic calls, analogous to IAT in PE.
        We scan .text for ``call`` instructions targeting any PLT section.
        """
        results: list[dict] = []
        text_sec = self._find_section(".text")
        if text_sec is None:
            return results

        # Collect all PLT-like sections (.plt, .plt.sec, .plt.got)
        plt_ranges: list[tuple[int, int]] = []
        for sec in self._bin.sections:
            if sec.name.startswith(".plt"):
                plt_ranges.append((sec.virtual_address, sec.virtual_address + sec.size))

        if not plt_ranges:
            return results

        # Build symbol map: PLT entry index -> symbol name
        # pltgot_relocations are ordered; PLT entries follow the same order
        plt_symbols: list[str] = []
        try:
            for rel in self._bin.pltgot_relocations:
                name = rel.symbol.name if rel.symbol else ""
                plt_symbols.append(name or f"unknown_{len(plt_symbols)}")
        except Exception:
            pass

        # Map PLT entry addresses to symbol names
        # .plt.sec (if present) has 16-byte entries, first entry is header
        plt_sec = self._find_section(".plt.sec") or self._find_section(".plt")
        if plt_sec is None:
            return results

        plt_base = plt_sec.virtual_address
        entry_size = 16  # typical x86-64 PLT entry size
        # .plt has a header entry; .plt.sec does not
        header_skip = 0 if ".sec" in plt_sec.name else 1

        plt_addr_map: dict[int, str] = {}
        for idx, sym_name in enumerate(plt_symbols):
            addr = plt_base + (idx + header_skip) * entry_size
            plt_addr_map[addr] = sym_name

        # Scan .text for E8 (call rel32) targeting PLT
        text_offset = text_sec.offset
        text_va = text_sec.virtual_address
        text_size = text_sec.size
        data = self._raw[text_offset:text_offset + text_size]

        i = 0
        while i < len(data) - 4:
            if data[i] == 0xE8:
                rel32 = int.from_bytes(data[i + 1:i + 5], "little", signed=True)
                call_va = text_va + i
                target = call_va + 5 + rel32
                # Check if target is in any PLT section
                in_plt = any(start <= target < end for start, end in plt_ranges)
                if in_plt:
                    func_name = plt_addr_map.get(target, f"plt_{target:#x}")
                    results.append({
                        "rva": call_va,
                        "target_dll": "",
                        "target_func": func_name,
                    })
            i += 1

        return results

    # ------------------------------------------------------------------
    # is_driver / is_kernel_module
    # ------------------------------------------------------------------
    def is_driver(self) -> bool:
        """Alias for is_kernel_module, matching PEAdapter interface."""
        return self.is_kernel_module()

    def is_kernel_module(self) -> bool:
        """Heuristic: check for .modinfo section or init_module / cleanup_module symbols."""
        for sec in self._bin.sections:
            if sec.name == ".modinfo":
                return True

        km_symbols = {"init_module", "cleanup_module", "__this_module"}
        all_names = set()
        try:
            for sym in self._bin.exported_symbols:
                all_names.add(sym.name)
        except Exception:
            pass
        try:
            for sym in self._bin.symbols:
                all_names.add(sym.name)
        except Exception:
            pass

        return bool(km_symbols & all_names)

    # ------------------------------------------------------------------
    # helpers
    # ------------------------------------------------------------------
    def _find_section(self, name: str):
        """Find a section by name, return lief Section or None."""
        for sec in self._bin.sections:
            if sec.name == name:
                return sec
        return None
