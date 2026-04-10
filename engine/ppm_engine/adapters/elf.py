"""
ELF adapter — extract structured info from ELF binaries using lief.
"""
from __future__ import annotations

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
        if self._bin.has_dynamic_entries:
            for entry in self._bin.dynamic_entries:
                if entry.tag == lief.ELF.DynamicEntry.TAG.NEEDED:
                    needed.append(entry.name)

        # Map symbols by their version library (best-effort)
        sym_lib_map: dict[str, str] = {}
        if hasattr(self._bin, "symbols_version_requirement"):
            for req in self._bin.symbols_version_requirement:
                lib = req.name
                for aux in req.auxiliary_symbols:
                    sym_lib_map[aux.name] = lib

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
    # is_kernel_module
    # ------------------------------------------------------------------
    def is_kernel_module(self) -> bool:
        """Heuristic: check for .modinfo section or init_module / cleanup_module symbols."""
        # Check for .modinfo section
        for sec in self._bin.sections:
            if sec.name == ".modinfo":
                return True

        # Check for kernel module init/cleanup symbols
        km_symbols = {"init_module", "cleanup_module", "__this_module"}
        all_names = set()
        for sym in self._bin.exported_symbols:
            all_names.add(sym.name)
        for sym in self._bin.static_symbols:
            all_names.add(sym.name)

        return bool(km_symbols & all_names)
