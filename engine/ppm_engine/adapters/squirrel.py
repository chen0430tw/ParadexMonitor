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
    data = Path(path).read_bytes()

    if not is_squirrel(data):
        return None

    info = SquirrelInfo()
    info.strings.append("Squirrel Installer (Electron)")

    # Find embedded ZIP (nupkg) - search for PK signature
    # The nupkg is typically the largest ZIP embedded in .rsrc
    best_zip = None
    best_count = 0
    idx = 0
    while idx < len(data) - 4:
        pos = data.find(b"PK\x03\x04", idx)
        if pos == -1:
            break
        try:
            zf = zipfile.ZipFile(io.BytesIO(data[pos:]))
            names = zf.namelist()
            if len(names) > best_count:
                best_count = len(names)
                best_zip = (pos, zf)
            else:
                zf.close()
        except Exception:
            pass
        idx = pos + 4
        if best_count > 10:
            break  # Good enough

    if best_zip:
        nupkg_offset, zf = best_zip
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
