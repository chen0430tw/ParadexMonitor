"""
Node.js SEA / Bun SEA adapter -- parse Single Executable Application packages.

Node.js SEA embeds JavaScript code into a PE via postject (resource injection).
Bun SEA uses a custom `.bun` PE section containing the bundled application.

Detection:
- Node.js SEA: NODE_SEA_BLOB or node:sea resource, or postject markers
- Bun SEA: PE with `.bun` section

These are increasingly common for distributing CLI tools (Claude Code uses Bun SEA).
"""
from __future__ import annotations

import struct
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class NodeSEAInfo:
    runtime: str = ""         # "node", "bun", "deno"
    runtime_version: str = ""
    app_section: str = ""     # section name containing the app (.bun, NODE_SEA_BLOB, etc.)
    app_size: int = 0         # size of the embedded application
    total_size: int = 0
    sections: list = field(default_factory=list)
    strings: list = field(default_factory=list)
    imports: dict = field(default_factory=dict)


# Known Node.js SEA markers
_NODE_SEA_MARKERS = [
    b"NODE_SEA_BLOB",
    b"NODE_SEA_FUSE",
    b"node:sea",
    b"postject",
]

# Known Bun markers
_BUN_MARKERS = [
    b"bun-",
    b"Bun v",
    b"bun.sh",
]


def is_node_sea(data: bytes) -> bool:
    """Check if PE is a Node.js or Bun Single Executable Application."""
    if data[:2] != b"MZ":
        return False
    # Check for .bun section or NODE_SEA markers
    # Quick check: search in first 1MB for markers
    header = data[:1024 * 1024]
    for marker in _NODE_SEA_MARKERS:
        if marker in header:
            return True
    # Check PE section names for .bun
    try:
        import pefile
        pe = pefile.PE(data=data, fast_load=True)
        for sec in pe.sections:
            name = sec.Name.rstrip(b"\x00").decode("ascii", errors="replace")
            if name == ".bun":
                pe.close()
                return True
        pe.close()
    except Exception:
        pass
    return False


def parse(path: str) -> Optional[NodeSEAInfo]:
    """Parse a Node.js/Bun SEA executable."""
    try:
        import pefile
    except ImportError:
        return None

    info = NodeSEAInfo()
    info.total_size = Path(path).stat().st_size

    try:
        pe = pefile.PE(path, fast_load=True)
    except Exception:
        return None

    # Parse sections
    bun_section = None
    for sec in pe.sections:
        name = sec.Name.rstrip(b"\x00").decode("ascii", errors="replace")
        size = sec.Misc_VirtualSize
        entropy = sec.get_entropy()
        info.sections.append({
            "name": name, "size": size, "entropy": round(entropy, 2)
        })

        if name == ".bun":
            bun_section = sec
            info.runtime = "bun"
            info.app_section = ".bun"
            info.app_size = size

    # Parse imports
    pe.parse_data_directories(directories=[1])
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll = entry.dll.decode("ascii", errors="replace")
            funcs = [imp.name.decode("ascii", errors="replace")
                     for imp in entry.imports if imp.name]
            info.imports[dll] = funcs

    pe.close()

    # Detect runtime type
    if not info.runtime:
        # Read first 2MB for markers
        with open(path, "rb") as f:
            header = f.read(2 * 1024 * 1024)

        for marker in _NODE_SEA_MARKERS:
            if marker in header:
                info.runtime = "node"
                info.app_section = "NODE_SEA_BLOB"
                break

        if not info.runtime:
            for marker in _BUN_MARKERS:
                if marker in header:
                    info.runtime = "bun"
                    break

    # Extract version strings
    with open(path, "rb") as f:
        # Read a sample for version detection
        sample = f.read(500000)

    import re
    # Bun version
    for m in re.finditer(rb"bun[- ]v?(\d+\.\d+\.\d+)", sample, re.IGNORECASE):
        info.runtime_version = m.group(1).decode("ascii")
        break
    # Node version
    if not info.runtime_version:
        for m in re.finditer(rb"node[/ ]v?(\d+\.\d+\.\d+)", sample, re.IGNORECASE):
            info.runtime_version = m.group(1).decode("ascii")
            break

    # Build strings
    info.strings.append(f"Runtime: {info.runtime or 'unknown'}")
    if info.runtime_version:
        info.strings.append(f"Version: {info.runtime_version}")
    if info.app_section:
        info.strings.append(f"App section: {info.app_section} ({info.app_size:,} bytes)")
    for sec in info.sections:
        info.strings.append(f"Section: {sec['name']} ({sec['size']:,} bytes, entropy={sec['entropy']})")
    for dll, funcs in info.imports.items():
        info.strings.append(f"Import: {dll} ({len(funcs)} functions)")

    return info
