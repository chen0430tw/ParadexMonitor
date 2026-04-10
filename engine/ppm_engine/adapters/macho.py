"""
Mach-O adapter — minimal stub with the same interface as PEAdapter / ELFAdapter.

TODO: Implement full parsing using lief when Mach-O analysis is needed.
"""
from __future__ import annotations


class MachOAdapter:
    """Stub adapter for Mach-O binaries. Methods return empty results."""

    def __init__(self, path: str) -> None:
        self.path = path
        # TODO: parse Mach-O with lief.MachO.parse()

    def imports(self) -> dict[str, list[str]]:
        """Return library -> [symbol, ...] mapping."""
        # TODO: extract LC_LOAD_DYLIB + bound symbols
        return {}

    def exports(self) -> list[str]:
        """Return exported symbol names."""
        # TODO: extract from export trie / LC_DYLD_INFO
        return []

    def sections(self) -> list[dict]:
        """Return section metadata."""
        # TODO: iterate segments/sections
        return []

    def entry_point(self) -> int:
        """Return entry point address."""
        # TODO: LC_MAIN or LC_UNIXTHREAD
        return 0

    def is_kernel_extension(self) -> bool:
        """Check if this is a kernel extension (.kext)."""
        # TODO: check for com.apple.kpi imports or __PRELINK sections
        return False
