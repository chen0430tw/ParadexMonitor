"""
InstallShield adapter -- parse InstallShield CAB installer packages.

Core algorithm ported from unshield (github.com/twogood/unshield).
Only extracts file listing and metadata for security analysis — no full extraction.

InstallShield CAB format:
- Signature: 0x28635349 ("ISc(")
- CommonHeader (20 bytes) → VolumeHeader → CabDescriptor → FileDescriptor[]
- Compression: zlib (DEFLATE)
- Versions: V5 (40-byte vol header), V6+ (64-byte vol header)
"""
from __future__ import annotations

import struct
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional

# InstallShield CAB signature
_CAB_SIGNATURE = 0x28635349  # "ISc("
_MSCF_SIGNATURE = 0x4643534D  # Microsoft CAB "MSCF" (not InstallShield)

# Common header: signature(4) + version(4) + volume_info(4) + desc_offset(4) + desc_size(4)
_COMMON_HEADER = struct.Struct("<I I I I I")  # 20 bytes

# File descriptor flags
_FILE_SPLIT = 1
_FILE_OBFUSCATED = 2
_FILE_COMPRESSED = 4
_FILE_INVALID = 8


@dataclass
class IShieldInfo:
    version: int = 0
    num_files: int = 0
    num_dirs: int = 0
    num_components: int = 0
    num_file_groups: int = 0
    files: list = field(default_factory=list)
    directories: list = field(default_factory=list)
    strings: list = field(default_factory=list)
    cab_size: int = 0


def is_installshield(path: str) -> bool:
    """Check for InstallShield CAB signature (0x28635349)."""
    try:
        with open(path, "rb") as f:
            sig = struct.unpack("<I", f.read(4))[0]
        return sig == _CAB_SIGNATURE
    except Exception:
        return False


def _read_string_at(data: bytes, offset: int) -> str:
    """Read null-terminated string at offset."""
    if offset >= len(data):
        return ""
    end = data.find(b"\x00", offset)
    if end == -1:
        end = min(offset + 256, len(data))
    try:
        return data[offset:end].decode("ascii", errors="replace")
    except Exception:
        return ""


def parse(path: str) -> Optional[IShieldInfo]:
    """Parse an InstallShield CAB (or .hdr) file and extract file listing."""
    p = Path(path)
    try:
        data = p.read_bytes()
    except Exception:
        return None

    if len(data) < 20:
        return None

    sig, version, volume_info, desc_offset, desc_size = _COMMON_HEADER.unpack_from(data, 0)

    if sig != _CAB_SIGNATURE:
        return None

    info = IShieldInfo()
    info.version = version
    info.cab_size = len(data)
    info.strings.append(f"InstallShield CAB v{version}")

    # V6+: descriptor is often in the .hdr file, not the .cab
    # If desc_size is 0, try to find the companion .hdr file
    if desc_size == 0 or desc_offset + desc_size > len(data):
        hdr_path = p.with_suffix(".hdr")
        if not hdr_path.exists():
            # Try data1.hdr in same directory
            hdr_path = p.parent / (p.stem + ".hdr")
        if hdr_path.exists():
            try:
                hdr_data = hdr_path.read_bytes()
                if len(hdr_data) >= 20:
                    h_sig, h_ver, h_vi, h_off, h_size = _COMMON_HEADER.unpack_from(hdr_data, 0)
                    if h_sig == _CAB_SIGNATURE and h_size > 0 and h_off + h_size <= len(hdr_data):
                        data = hdr_data
                        desc_offset = h_off
                        desc_size = h_size
                        info.strings.append(f"Header from: {hdr_path.name}")
            except Exception:
                pass

    if desc_size == 0 or desc_offset + desc_size > len(data):
        return info

    desc = data[desc_offset:desc_offset + desc_size]

    # CabDescriptor layout (version-dependent, but common fields):
    # +0x00: desc_offset_in_file (4)
    # +0x04: ... (varies)
    # Key fields at known offsets for V5/V6:
    #   file_table_offset, file_table_size, file_table_size2
    #   directory_count, file_count
    #   file_table_offset2
    # The exact layout varies significantly between versions.

    # For V5 (version < 6):
    #   +0x0C: file_table_offset (4)
    #   +0x10: file_table_size (4)  [0x14: file_table_size2]
    #   +0x18: directory_count (4)
    #   +0x24: file_count (4)
    #   +0x28: file_table_offset2 (4)

    # For V6+:
    #   +0x12: file_table_offset (4)
    #   +0x16: file_table_size (4)  [0x1A: file_table_size2]
    #   +0x1E: directory_count (4)
    #   +0x2A: file_count (4)
    #   +0x2E: file_table_offset2 (4)

    try:
        # CabDescriptor field offsets (from unshield libunshield.c):
        # Both V5 and V6 use the same descriptor layout:
        #   +0x0C: file_table_offset
        #   +0x14: file_table_size
        #   +0x18: file_table_size2
        #   +0x1C: directory_count
        #   +0x28: file_count
        #   +0x2C: file_table_offset2
        if len(desc) > 0x30:
            file_table_off = struct.unpack_from("<I", desc, 0x0C)[0]
            file_table_size = struct.unpack_from("<I", desc, 0x14)[0]
            file_table_size2 = struct.unpack_from("<I", desc, 0x18)[0]
            dir_count = struct.unpack_from("<I", desc, 0x1C)[0]
            file_count = struct.unpack_from("<I", desc, 0x28)[0]
            file_table_off2 = struct.unpack_from("<I", desc, 0x2C)[0]
        else:
            return info

        info.num_dirs = dir_count
        info.num_files = file_count
        info.strings.append(f"Directories: {dir_count}")
        info.strings.append(f"Files: {file_count}")

        # File table: array of uint32 offsets at desc_offset + file_table_offset
        # First directory_count entries are directories, next file_count are files
        # Each offset points to a string relative to file table start
        ft_abs = desc_offset + file_table_off  # absolute offset in data
        total_entries = dir_count + file_count
        file_table = []
        for i in range(min(total_entries, 10000)):
            pos = ft_abs + i * 4
            if pos + 4 > len(data):
                break
            file_table.append(struct.unpack_from("<I", data, pos)[0])

        # Read directory names (first dir_count entries)
        for i in range(min(dir_count, len(file_table))):
            name = _read_string_at(data, ft_abs + file_table[i])
            if name:
                info.directories.append(name)
                info.strings.append(f"Dir: {name}")

        # Read file descriptors (next file_count entries)
        # File descriptor is at the offset pointed to by file_table[dir_count + i]
        # Each descriptor starts with: name_offset(4) + dir_index(4) + flags(2) + sizes...
        for i in range(min(file_count, len(file_table) - dir_count)):
            ft_idx = dir_count + i
            if ft_idx >= len(file_table):
                break
            fd_abs = ft_abs + file_table[ft_idx]
            if fd_abs + 0x14 > len(data):
                break

            try:
                name_off = struct.unpack_from("<I", data, fd_abs)[0]
                dir_idx = struct.unpack_from("<I", data, fd_abs + 4)[0]
                flags = struct.unpack_from("<H", data, fd_abs + 8)[0]
                exp_size = struct.unpack_from("<I", data, fd_abs + 0x0A)[0]
                comp_size = struct.unpack_from("<I", data, fd_abs + 0x12)[0]

                fname = _read_string_at(data, ft_abs + name_off)
                if not fname:
                    fname = f"file_{i}"

                dirname = info.directories[dir_idx] if dir_idx < len(info.directories) else ""
                fullpath = f"{dirname}\\{fname}" if dirname else fname

                info.files.append(fullpath)

                attrs = []
                if flags & _FILE_COMPRESSED: attrs.append("compressed")
                if flags & _FILE_OBFUSCATED: attrs.append("obfuscated")
                if flags & _FILE_SPLIT: attrs.append("split")
                attr_str = f" [{','.join(attrs)}]" if attrs else ""
                info.strings.append(f"File: {fullpath} ({exp_size} bytes){attr_str}")

                lower = fname.lower()
                if lower.endswith(('.exe', '.dll', '.sys', '.scr', '.bat', '.cmd', '.ps1', '.vbs')):
                    info.strings.append(f"Executable: {fullpath}")
            except Exception:
                continue

    except Exception:
        pass

    return info
