"""
PyInstaller adapter -- parse PyInstaller-packaged executables.

PyInstaller bundles Python scripts + dependencies into a single .exe.
Common packaging method for Python-based malware (stealers, RATs, miners).

Detects PyInstaller signature, extracts TOC (Table of Contents),
identifies the main script and bundled modules.
"""
from __future__ import annotations

import struct
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional


# PyInstaller archive magic (at end of file, before CArchive cookie)
_PYINST_MAGIC = b"MEI\x0C\x0B\x0A\x0B\x0E"  # 8 bytes

# CArchive cookie struct (PyInstaller 2.1+):
# magic(8) + pkg_length(4) + toc_offset(4) + toc_length(4) + python_ver(4) + pylib_name(64)
_COOKIE_SIZE = 88  # 8 + 4 + 4 + 4 + 4 + 64

# TOC entry types
_TOC_TYPES = {
    ord('b'): "binary",      # binary dependency
    ord('d'): "data",        # data file
    ord('m'): "module",      # Python module (.pyc)
    ord('M'): "pkg_module",  # Python package module
    ord('n'): "pyz_dep",     # PYZ dependency
    ord('o'): "option",      # runtime option
    ord('s'): "script",      # Python script (entry point)
    ord('z'): "pyz",         # PYZ archive (bundled .pyc)
    ord('Z'): "splash",      # splash screen
}


@dataclass
class PyInstInfo:
    python_version: str = ""
    pylib_name: str = ""
    entry_scripts: list = field(default_factory=list)
    modules: list = field(default_factory=list)
    binaries: list = field(default_factory=list)
    data_files: list = field(default_factory=list)
    strings: list = field(default_factory=list)
    num_files: int = 0
    pkg_size: int = 0


def is_pyinstaller(data: bytes) -> bool:
    """Check for PyInstaller MEI magic near end of file."""
    # Magic is in the last ~4KB of the file
    tail = data[-4096:] if len(data) > 4096 else data
    return _PYINST_MAGIC in tail


def parse(path: str) -> Optional[PyInstInfo]:
    """Parse a PyInstaller executable and extract TOC."""
    data = Path(path).read_bytes()

    # Find cookie (MEI magic near end of file)
    idx = data.rfind(_PYINST_MAGIC)
    if idx == -1:
        return None

    if idx + _COOKIE_SIZE > len(data):
        return None

    info = PyInstInfo()

    # Parse cookie
    cookie = data[idx:]
    magic = cookie[:8]
    pkg_length = struct.unpack_from(">I", cookie, 8)[0]
    toc_offset = struct.unpack_from(">I", cookie, 12)[0]
    toc_length = struct.unpack_from(">I", cookie, 16)[0]
    python_ver = struct.unpack_from(">I", cookie, 20)[0]
    pylib_name = cookie[24:88].split(b"\x00")[0].decode("ascii", errors="replace")

    info.python_version = f"{python_ver // 100}.{python_ver % 100}"
    info.pylib_name = pylib_name
    info.pkg_size = pkg_length
    info.strings.append(f"Python {info.python_version}")
    info.strings.append(f"PyLib: {pylib_name}")

    # Calculate package start
    pkg_start = idx + _COOKIE_SIZE - pkg_length
    if pkg_start < 0:
        pkg_start = 0

    # Parse TOC
    toc_data = data[pkg_start + toc_offset:pkg_start + toc_offset + toc_length]
    pos = 0
    while pos < len(toc_data) - 18:
        # TOC entry: entry_length(4) + data_offset(4) + data_length(4) +
        #            uncomp_length(4) + compress_flag(1) + type_code(1) + name(variable)
        entry_len = struct.unpack_from(">I", toc_data, pos)[0]
        if entry_len < 18 or entry_len > 65536:
            break
        data_off = struct.unpack_from(">I", toc_data, pos + 4)[0]
        data_len = struct.unpack_from(">I", toc_data, pos + 8)[0]
        uncomp_len = struct.unpack_from(">I", toc_data, pos + 12)[0]
        compress = toc_data[pos + 16]
        typecode = toc_data[pos + 17]
        name = toc_data[pos + 18:pos + entry_len].split(b"\x00")[0].decode("utf-8", errors="replace")

        entry_type = _TOC_TYPES.get(typecode, f"type_{chr(typecode)}" if 0x20 <= typecode < 0x7f else f"type_0x{typecode:02x}")

        if typecode == ord('s'):
            info.entry_scripts.append(name)
            info.strings.append(f"EntryScript: {name}")
        elif typecode in (ord('m'), ord('M')):
            info.modules.append(name)
            info.strings.append(f"Module: {name}")
        elif typecode == ord('b'):
            info.binaries.append(name)
            info.strings.append(f"Binary: {name}")
        elif typecode == ord('d'):
            info.data_files.append(name)
            info.strings.append(f"Data: {name}")
        else:
            info.strings.append(f"{entry_type}: {name}")

        pos += entry_len

    info.num_files = len(info.entry_scripts) + len(info.modules) + len(info.binaries) + len(info.data_files)
    return info
