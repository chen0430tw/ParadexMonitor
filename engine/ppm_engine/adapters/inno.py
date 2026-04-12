"""
Inno Setup adapter -- parse Inno Setup installer packages.

Detects Inno Setup signature, extracts setup headers and string data.
Full script decompilation requires innounp/innoextract (external tools);
this adapter focuses on string extraction for pattern analysis.

Inno Setup versions 1.x-6.x are widely used for both legitimate and
malicious software distribution.
"""
from __future__ import annotations

import re
import struct
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional


# Inno Setup signatures (version-dependent)
_INNO_SIGNATURES = [
    b"Inno Setup Setup Data",
    b"Inno Setup Messages",
    b"rDlPtS\x02\x07tS",  # Inno Setup 5.x+
    b"rDlPtS",             # Inno Setup 5.x compressed
    b"zlb\x1a",            # Inno Setup LZMA block
]

# Inno Setup version strings found in PE resources or overlay
_INNO_VERSION_RE = re.compile(rb"Inno Setup Setup Data \((\d+\.\d+\.\d+)\)")


@dataclass
class InnoInfo:
    version: str = ""
    app_name: str = ""
    app_version: str = ""
    publisher: str = ""
    files: list = field(default_factory=list)
    strings: list = field(default_factory=list)
    num_files: int = 0
    compression: str = ""


def is_inno_setup(data: bytes) -> bool:
    """Check if file contains Inno Setup signature."""
    for sig in _INNO_SIGNATURES:
        if sig in data[:512 * 1024]:
            return True
    return False


def parse(path: str) -> Optional[InnoInfo]:
    """Parse an Inno Setup installer and extract strings."""
    data = Path(path).read_bytes()

    if not is_inno_setup(data):
        return None

    info = InnoInfo()

    # Detect version
    m = _INNO_VERSION_RE.search(data[:512 * 1024])
    if m:
        info.version = m.group(1).decode("ascii", errors="replace")
        info.strings.append(f"Inno Setup {info.version}")

    # Detect compression
    if b"zlb\x1a" in data[:1024 * 1024]:
        info.compression = "lzma"
    elif b"\x78\x9C" in data[:1024]:
        info.compression = "zlib"
    else:
        info.compression = "unknown"

    # Extract readable strings from the overlay data
    # Inno Setup stores setup info as Pascal-style strings in the header
    # After the PE stub, there's setup data containing all configuration

    # Find the Inno header
    for sig in _INNO_SIGNATURES:
        idx = data.find(sig)
        if idx != -1:
            header_start = idx
            break
    else:
        header_start = len(data) // 2  # fallback to middle of file

    # Extract all readable strings from header area
    overlay = data[header_start:]

    # Try to decompress LZMA blocks
    strings_found = set()

    # Method 1: direct UTF-16LE strings (newer Inno Setup)
    for m in re.finditer(rb"(?:[\x20-\x7e]\x00){6,}", overlay[:256 * 1024]):
        s = m.group().decode("utf-16-le", errors="replace").strip()
        if s and s not in strings_found:
            strings_found.add(s)

    # Method 2: ASCII strings
    for m in re.finditer(rb"[\x20-\x7e]{8,}", overlay[:256 * 1024]):
        s = m.group().decode("ascii", errors="replace").strip()
        if s and s not in strings_found:
            strings_found.add(s)

    # Method 3: try LZMA decompression of blocks
    lzma_idx = overlay.find(b"zlb\x1a")
    if lzma_idx != -1:
        try:
            import lzma
            # Inno Setup LZMA: "zlb" + 0x1A + compressed data
            compressed = overlay[lzma_idx + 4:]
            # Try raw LZMA
            for try_off in range(0, 20):
                try:
                    props = compressed[try_off:try_off + 5]
                    filt = lzma._decode_filter_properties(lzma.FILTER_LZMA1, props)
                    decompressed = lzma.decompress(compressed[try_off + 5:try_off + 5 + 65536],
                                                   lzma.FORMAT_RAW, filters=[filt])
                    if len(decompressed) > 100:
                        for m in re.finditer(rb"[\x20-\x7e]{8,}", decompressed):
                            s = m.group().decode("ascii", errors="replace").strip()
                            if s and s not in strings_found:
                                strings_found.add(s)
                        break
                except Exception:
                    continue
        except ImportError:
            pass

    # Filter and categorize strings
    for s in sorted(strings_found):
        # Detect app metadata
        if "AppName" in s or "AppVerName" in s:
            info.strings.append(f"Meta: {s}")
        elif s.endswith(('.exe', '.dll', '.sys', '.bat', '.cmd', '.ps1', '.vbs')):
            info.strings.append(f"File: {s}")
            info.files.append(s)
        elif '\\' in s and len(s) > 10:
            info.strings.append(f"Path: {s}")
        elif 'HKLM' in s or 'HKCU' in s or 'Registry' in s.lower():
            info.strings.append(f"Registry: {s}")
        elif len(s) > 5:
            info.strings.append(s)

    info.num_files = len(info.files)
    return info
