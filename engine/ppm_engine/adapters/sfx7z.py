"""
7z SFX (Self-Extracting Archive) adapter -- parse 7-Zip self-extracting packages.

Detects 7z magic after PE stub, extracts file list and metadata.
Common delivery method for ransomware and malware droppers.
"""
from __future__ import annotations

import struct
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional


# 7z magic: 37 7A BC AF 27 1C
_7Z_MAGIC = b"\x37\x7A\xBC\xAF\x27\x1C"


@dataclass
class SFX7zInfo:
    stub_size: int = 0
    archive_size: int = 0
    files: list = field(default_factory=list)
    strings: list = field(default_factory=list)
    num_files: int = 0
    method: str = ""  # compression method


def is_sfx7z(data: bytes) -> bool:
    """Check if PE contains embedded 7z archive."""
    return data[:2] == b"MZ" and _7Z_MAGIC in data[:2 * 1024 * 1024]


def parse(path: str) -> Optional[SFX7zInfo]:
    """Parse a 7z SFX and extract file listing."""
    data = Path(path).read_bytes()

    # Find 7z magic after PE stub
    idx = data.find(_7Z_MAGIC)
    if idx == -1 or idx < 100:  # Must be after PE stub
        return None

    info = SFX7zInfo()
    info.stub_size = idx
    info.archive_size = len(data) - idx

    try:
        import py7zr
        with py7zr.SevenZipFile(path, 'r') as z:
            for entry in z.list():
                fname = entry.filename
                info.files.append(fname)
                info.strings.append(f"File: {fname}")

                # Flag suspicious file types
                lower = fname.lower()
                if lower.endswith(('.exe', '.dll', '.sys', '.scr', '.pif', '.bat', '.cmd', '.ps1', '.vbs', '.js')):
                    info.strings.append(f"Executable: {fname}")

            # Get compression info
            try:
                info.method = str(z.archiveinfo().method_names) if hasattr(z, 'archiveinfo') else ""
            except Exception:
                pass

    except Exception:
        # Fallback: just report the 7z offset
        info.strings.append(f"7z archive at offset {idx} ({info.archive_size} bytes)")

    info.num_files = len(info.files)
    return info
