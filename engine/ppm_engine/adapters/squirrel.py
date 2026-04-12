"""
Squirrel adapter -- parse Electron/Squirrel installer packages.

Squirrel is the update/install framework used by Electron apps
(Discord, Slack, VS Code, Claude Desktop, etc.).

Format: PE32 stub + embedded .nupkg (NuGet package = ZIP) in .rsrc section.
Detection: PE with "Squirrel" or "SquirrelInstall" strings + large .rsrc section.
"""
from __future__ import annotations

import struct
import re
import zipfile
import io
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class SquirrelInfo:
    app_name: str = ""
    app_version: str = ""
    nupkg_offset: int = 0
    nupkg_size: int = 0
    files: list = field(default_factory=list)
    strings: list = field(default_factory=list)
    num_files: int = 0
    has_update_exe: bool = False
    nuspec_content: str = ""


def is_squirrel(data: bytes) -> bool:
    """Check if PE contains Squirrel installer markers."""
    if data[:2] != b"MZ":
        return False
    # Search for Squirrel signatures in first 200KB (PE stub area)
    header = data[:200000]
    return (b"S\x00q\x00u\x00i\x00r\x00r\x00e\x00l" in header or  # UTF-16LE "Squirrel"
            b"SquirrelInstall" in header or
            b"S\x00q\x00u\x00i\x00r\x00r\x00e\x00l\x00I\x00n\x00s\x00t\x00a\x00l\x00l" in header)


def parse(path: str) -> Optional[SquirrelInfo]:
    """Parse a Squirrel installer and extract embedded nupkg contents."""
    fsize = Path(path).stat().st_size

    # Only read header (200KB) for Squirrel detection — don't load entire file
    with open(path, "rb") as f:
        header = f.read(200000)
    if not is_squirrel(header):
        return None

    info = SquirrelInfo()
    info.strings.append("Squirrel Installer (Electron)")

    # Find embedded nupkg using EOCD (End of Central Directory) from file tail.
    # Only reads the last 65KB + the ZIP Central Directory — no full file load.
    zip_start = -1
    nupkg_zf = None

    with open(path, "rb") as f:
        # Read tail to find EOCD
        tail_size = min(fsize, 65536 + 22)
        f.seek(fsize - tail_size)
        tail = f.read(tail_size)
        eocd_pos = tail.rfind(b"PK\x05\x06")

        if eocd_pos != -1:
            eocd_abs = fsize - tail_size + eocd_pos
            cd_offset = struct.unpack_from("<I", tail, eocd_pos + 16)[0]

            # Find first PK\x03\x04 near the CD offset area
            search_pos = max(0, cd_offset - 256)
            f.seek(search_pos)
            chunk = f.read(512)
            pk_idx = chunk.find(b"PK\x03\x04")
            if pk_idx != -1:
                zip_start = search_pos + pk_idx

    # Open ZIP directly from file (zipfile handles offset-based reads)
    if zip_start >= 0:
        try:
            # Create a wrapper that offsets reads
            class OffsetFile:
                def __init__(self, fp, offset, size):
                    self._fp = open(fp, "rb")
                    self._offset = offset
                    self._size = size
                    self._pos = 0
                def read(self, n=-1):
                    self._fp.seek(self._offset + self._pos)
                    if n == -1: n = self._size - self._pos
                    data = self._fp.read(min(n, self._size - self._pos))
                    self._pos += len(data)
                    return data
                def seek(self, pos, whence=0):
                    if whence == 0: self._pos = pos
                    elif whence == 1: self._pos += pos
                    elif whence == 2: self._pos = self._size + pos
                def tell(self): return self._pos
                def close(self): self._fp.close()
                def __enter__(self): return self
                def __exit__(self, *a): self.close()

            of = OffsetFile(path, zip_start, fsize - zip_start)
            nupkg_zf = zipfile.ZipFile(of)
        except Exception:
            pass

    if nupkg_zf:
        zf = nupkg_zf
        info.nupkg_offset = zip_start
        info.nupkg_offset = nupkg_offset
        info.strings.append(f"NuPkg at offset {nupkg_offset}")

        for name in zf.namelist():
            info.files.append(name)
            lower = name.lower()
            if lower.endswith(('.exe', '.dll')):
                info.strings.append(f"Executable: {name}")
            elif lower.endswith(('.node', '.asar')):
                info.strings.append(f"Node module: {name}")

            # Check for Update.exe
            if lower.endswith("update.exe"):
                info.has_update_exe = True

        # Parse .nuspec for metadata
        nuspecs = [n for n in zf.namelist() if n.endswith('.nuspec')]
        if nuspecs:
            try:
                nuspec = zf.read(nuspecs[0]).decode('utf-8', errors='replace')
                info.nuspec_content = nuspec[:2000]

                # Extract metadata from XML
                import xml.etree.ElementTree as ET
                root = ET.fromstring(nuspec)
                ns = ""
                if root.tag.startswith("{"):
                    ns = root.tag.split("}")[0] + "}"
                id_el = root.find(f".//{ns}id")
                ver_el = root.find(f".//{ns}version")
                if id_el is not None and id_el.text:
                    info.app_name = id_el.text
                    info.strings.append(f"App: {id_el.text}")
                if ver_el is not None and ver_el.text:
                    info.app_version = ver_el.text
                    info.strings.append(f"Version: {ver_el.text}")
            except Exception:
                pass

        zf.close()

    info.num_files = len(info.files)
    return info
