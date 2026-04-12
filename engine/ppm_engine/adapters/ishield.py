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
    """Parse an InstallShield CAB file and extract file listing."""
    try:
        data = Path(path).read_bytes()
    except Exception:
        return None

    if len(data) < 20:
        return None

    # Parse common header
    sig, version, volume_info, desc_offset, desc_size = _COMMON_HEADER.unpack_from(data, 0)

    if sig != _CAB_SIGNATURE:
        return None

    info = IShieldInfo()
    info.version = version
    info.cab_size = len(data)
    info.strings.append(f"InstallShield CAB v{version}")

    # Check if descriptor is within file bounds
    if desc_offset + desc_size > len(data) or desc_size < 100:
        # Can't parse descriptor, just report basic info
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
        if version < 6:
            # V5 layout
            if len(desc) > 0x30:
                file_table_off = struct.unpack_from("<I", desc, 0x0C)[0]
                dir_count = struct.unpack_from("<I", desc, 0x18)[0]
                file_count = struct.unpack_from("<I", desc, 0x24)[0]
                file_table_off2 = struct.unpack_from("<I", desc, 0x28)[0]
            else:
                return info
        else:
            # V6+ layout
            if len(desc) > 0x36:
                file_table_off = struct.unpack_from("<I", desc, 0x12)[0]
                dir_count = struct.unpack_from("<I", desc, 0x1E)[0]
                file_count = struct.unpack_from("<I", desc, 0x2A)[0]
                file_table_off2 = struct.unpack_from("<I", desc, 0x2E)[0]
            else:
                return info

        info.num_dirs = dir_count
        info.num_files = file_count
        info.strings.append(f"Directories: {dir_count}")
        info.strings.append(f"Files: {file_count}")

        # Read directory names from file table
        # Directory entries are at file_table_off, each is a 4-byte offset to string
        ft_base = desc_offset + file_table_off
        for i in range(min(dir_count, 256)):
            name_off_pos = ft_base + i * 4
            if name_off_pos + 4 > len(data):
                break
            name_off = struct.unpack_from("<I", data, name_off_pos)[0]
            name = _read_string_at(data, ft_base + name_off)
            if name:
                info.directories.append(name)
                info.strings.append(f"Dir: {name}")

        # Read file descriptors
        # File descriptors start after directory table
        # V5: each descriptor is 0x3A bytes
        # V6: each descriptor is 0x57 bytes
        fd_size = 0x3A if version < 6 else 0x57
        fd_base = ft_base + file_table_off2 if file_table_off2 else ft_base + dir_count * 4

        for i in range(min(file_count, 10000)):
            fd_pos = fd_base + i * fd_size
            if fd_pos + fd_size > len(data):
                break

            try:
                # Common fields at start of file descriptor:
                # +0x00: name_offset (4)
                # +0x04: directory_index (4)
                # +0x08: flags (2)
                # +0x0A: expanded_size (4) [or 8 bytes for V6+]
                # +0x0E: compressed_size (4) [or 8 bytes for V6+]
                name_off = struct.unpack_from("<I", data, fd_pos)[0]
                dir_idx = struct.unpack_from("<I", data, fd_pos + 4)[0]
                flags = struct.unpack_from("<H", data, fd_pos + 8)[0]

                if version < 6:
                    exp_size = struct.unpack_from("<I", data, fd_pos + 0x0A)[0]
                    comp_size = struct.unpack_from("<I", data, fd_pos + 0x0E)[0]
                else:
                    exp_size = struct.unpack_from("<Q", data, fd_pos + 0x0A)[0]
                    comp_size = struct.unpack_from("<Q", data, fd_pos + 0x12)[0]

                # Read filename
                fname = _read_string_at(data, ft_base + name_off)
                if not fname:
                    fname = f"file_{i}"

                # Build full path
                dirname = info.directories[dir_idx] if dir_idx < len(info.directories) else ""
                fullpath = f"{dirname}\\{fname}" if dirname else fname

                info.files.append(fullpath)

                # Flag attributes
                attrs = []
                if flags & _FILE_COMPRESSED:
                    attrs.append("compressed")
                if flags & _FILE_OBFUSCATED:
                    attrs.append("obfuscated")
                if flags & _FILE_SPLIT:
                    attrs.append("split")

                attr_str = f" [{','.join(attrs)}]" if attrs else ""
                info.strings.append(f"File: {fullpath} ({exp_size} bytes){attr_str}")

                # Flag suspicious files
                lower = fname.lower()
                if lower.endswith(('.exe', '.dll', '.sys', '.scr', '.bat', '.cmd', '.ps1', '.vbs')):
                    info.strings.append(f"Executable: {fullpath}")

            except Exception:
                continue

    except Exception:
        pass

    return info
