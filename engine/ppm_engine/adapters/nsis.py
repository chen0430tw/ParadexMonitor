"""
NSIS (Nullsoft Scriptable Install System) adapter -- parse NSIS installer/uninstaller packages.

Extracts:
- NSIS version (2 or 3, Unicode or ANSI)
- Compression method (LZMA, Zlib, Bzip2)
- String table (all embedded strings: file paths, registry keys, commands)
- Script entries (bytecode opcodes with string references)
- Embedded files list

Reference: NSIS source code (nsis.sourceforge.io)
Inspired by: nrs (NSIS Reversing Suite)
"""
from __future__ import annotations

import struct
import re
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional

# First header constants
_FH_SIG = 0xDEADBEEF
_FH_MAGIC = b"NullsoftInst"

# Block type IDs
NB_PAGES = 0
NB_SECTIONS = 1
NB_ENTRIES = 2
NB_STRINGS = 3
NB_LANGTABLES = 4
NB_CTLCOLORS = 5
NB_BGFONT = 6
NB_DATA = 7
_BLOCKS_COUNT = 8

# NSIS opcodes (most common ones for script reconstruction)
_OPCODES = {
    0: "Invalid",
    1: "Return",
    2: "Nop",
    3: "Abort",
    4: "Quit",
    5: "Call",
    6: "UpdateText",
    7: "Sleep",
    8: "BringToFront",
    9: "ChDir",
    10: "Log",
    11: "FindDir",
    12: "SetFileAttributes",
    13: "CreateDir",
    14: "IfFileExists",
    15: "SetFlag",
    16: "IfFlag",
    17: "GetFlag",
    18: "Rename",
    19: "GetFullPathName",
    20: "SearchPath",
    21: "GetTempFileName",
    22: "ExtractFile",
    23: "DeleteFile",
    24: "MessageBox",
    25: "RMDir",
    26: "StrLen",
    27: "StrCpy",
    28: "StrCmp",
    29: "ReadEnvStr",
    30: "IntCmp",
    31: "IntCmpU",
    32: "IntOp",
    33: "IntFmt",
    34: "PushPop",
    35: "FindWindow",
    36: "SendMessage",
    37: "IsWindow",
    38: "GetDlgItem",
    39: "SetCtlColors",
    40: "SetBrandingImage",
    41: "CreateFont",
    42: "ShowWindow",
    43: "ShellExec",
    44: "Execute",
    45: "GetFileTime",
    46: "GetDLLVersion",
    47: "RegisterDLL",
    48: "CreateShortcut",
    49: "CopyFiles",
    50: "Reboot",
    51: "WriteINI",
    52: "ReadINIStr",
    53: "DeleteINISec",
    54: "DeleteINIStr",
    55: "FlushINI",
    56: "FindFirst",
    57: "FindNext",
    58: "FindClose",
    59: "FileOpen",
    60: "FileClose",
    61: "FileSeek",
    62: "FileRead",
    63: "FileWrite",
    64: "FileReadByte",
    65: "FileWriteByte",
    66: "FindProc",
    67: "SetDetailsView",
    68: "SetDetailsPrint",
    69: "SetAutoClose",
    70: "SetOverwrite",
    71: "SetDatablockOptimize",
    72: "SetDateSave",
    73: "SetCompress",
    74: "GetLabelAddress",
    75: "GetCurrentAddress",
    76: "SectionSetFlags",
    77: "SectionGetFlags",
    78: "SectionSetText",
    79: "SectionGetText",
    80: "GetCurrentInstType",
    81: "SetCurInstType",
    82: "SetRegView",
    83: "SetShellVarContext",
    84: "WriteReg",
    85: "DeleteReg",
    86: "WriteRegBin",
    87: "WriteUninstaller",
    88: "SectionSetInsttypes",
    89: "GetLabelAddr2",
    90: "GetFunctionAddr",
    91: "LockWindow",
    92: "FileReadUTF16LE",
    93: "FileReadWord",
    94: "FileWriteUTF16LE",
    95: "FileWriteWord",
    96: "MiscOp",
}

# FirstHeader struct: flags(4) + siginfo(4) + magics(12) + comp_size(4) + decomp_size(4)
_FH_STRUCT = struct.Struct("<I I 12s I I")
# 28 bytes total

# Block header: offset(4) + num_items(4)
_BH_STRUCT = struct.Struct("<I I")

# Entry: opcode(4) + params[6](24)
_ENTRY_STRUCT = struct.Struct("<I 6I")


@dataclass
class NSISInfo:
    """Parsed NSIS installer information."""
    version: int = 3            # 2 or 3
    unicode: bool = True        # True for NSIS3 Unicode
    is_uninstaller: bool = False
    compression: str = "unknown"  # "lzma", "zlib", "bzip2"
    strings: list = field(default_factory=list)
    entries: list = field(default_factory=list)  # list of (opcode_name, params)
    sections: list = field(default_factory=list)
    num_entries: int = 0
    num_strings: int = 0
    stub_size: int = 0
    header_size: int = 0


def is_nsis(data: bytes) -> bool:
    """Quick check: does this PE contain an NSIS firstheader?"""
    return _find_firstheader_offset(data) is not None


def _find_firstheader_offset(data: bytes) -> Optional[int]:
    """Scan for NullsoftInst + DEADBEEF signature in file data."""
    # NSIS firstheader is at the end of the PE stub.
    # Search for the magic in the first 1MB (typical PE stubs are 50-200KB).
    search_limit = min(len(data), 1024 * 1024)
    idx = 0
    while idx < search_limit:
        pos = data.find(_FH_MAGIC, idx, search_limit)
        if pos == -1:
            return None
        # Magic is at offset +8 in firstheader, so firstheader starts at pos-8
        fh_start = pos - 8
        if fh_start < 0:
            idx = pos + 1
            continue
        # Check DEADBEEF at offset +4
        sig = struct.unpack_from("<I", data, fh_start + 4)[0]
        if sig == _FH_SIG:
            return fh_start
        idx = pos + 1
    return None


def _detect_compression(data: bytes) -> str:
    """Detect NSIS compression method from first bytes of compressed data."""
    if len(data) < 6:
        return "unknown"
    if data[0:3] == bytes([0x5D, 0, 0]) and data[5] == 0:
        return "lzma"
    if data[0] <= 1 and data[1] == 0x5D and data[2] == 0 and data[3] == 0:
        return "lzma"  # with filter byte prefix
    if data[0] == 0x31 and data[1] < 0x0E:
        return "bzip2"
    return "zlib"


def _decompress(data: bytes, method: str) -> bytes:
    """Decompress NSIS data block."""
    if method == "lzma":
        import lzma
        # NSIS LZMA: 5 bytes props + raw compressed data
        offset = 0
        if data[0] <= 1 and data[1] == 0x5D:
            offset = 1  # skip filter byte
        props = data[offset:offset + 5]
        try:
            filt = lzma._decode_filter_properties(lzma.FILTER_LZMA1, props)
            return lzma.decompress(data[offset + 5:], lzma.FORMAT_RAW, filters=[filt])
        except Exception:
            return b""
    elif method == "zlib":
        import zlib
        try:
            return zlib.decompress(data, -zlib.MAX_WBITS)
        except Exception:
            return b""
    elif method == "bzip2":
        import bz2
        try:
            return bz2.decompress(data)
        except Exception:
            return b""
    return b""


def _extract_strings_nsis3(block: bytes) -> list[str]:
    """Extract null-terminated UTF-16LE strings from NSIS3 string block."""
    strings = []
    i = 0
    while i < len(block) - 1:
        # Find null terminator (two zero bytes, aligned)
        end = i
        while end < len(block) - 1:
            if block[end] == 0 and block[end + 1] == 0:
                break
            end += 2
        if end > i:
            try:
                s = block[i:end].decode("utf-16-le", errors="replace")
                # Filter out NSIS escape codes (low codepoints used as variable refs)
                s = re.sub(r"[\x01-\x04].", "", s)
                if s and len(s) > 0:
                    strings.append(s)
            except Exception:
                pass
        i = end + 2
    return strings


def _extract_strings_nsis2(block: bytes) -> list[str]:
    """Extract null-terminated ASCII strings from NSIS2 string block."""
    strings = []
    i = 0
    while i < len(block):
        end = block.find(b"\x00", i)
        if end == -1:
            break
        if end > i:
            try:
                s = block[i:end].decode("ascii", errors="replace")
                s = re.sub(r"[\xfc-\xff].", "", s)
                if s:
                    strings.append(s)
            except Exception:
                pass
        i = end + 1
    return strings


def parse(path: str) -> Optional[NSISInfo]:
    """Parse an NSIS installer and extract strings + script entries."""
    data = Path(path).read_bytes()

    fh_offset = _find_firstheader_offset(data)
    if fh_offset is None:
        return None

    info = NSISInfo()
    info.stub_size = fh_offset

    # Parse firstheader
    flags, sig, magic, comp_size, decomp_size = _FH_STRUCT.unpack_from(data, fh_offset)
    info.is_uninstaller = bool(flags & 1)
    info.header_size = comp_size

    # Compressed data starts right after firstheader
    data_offset = fh_offset + _FH_STRUCT.size
    compressed = data[data_offset:]

    # Decompress: try solid (whole stream) then non-solid (skip 4-byte size prefix).
    # NSIS uses LZMA, Zlib, or Bzip2. Solid = entire archive in one stream.
    inflated = b""
    for try_offset in [0, 4]:  # 0 = solid, 4 = non-solid (skip size prefix)
        comp_data = compressed[try_offset:]
        for method in ["lzma", "zlib", "bzip2"]:
            try:
                result = _decompress(comp_data, method)
                if result and len(result) > 100:
                    inflated = result
                    info.compression = method
                    break
            except Exception:
                continue
        if inflated:
            break

    if not inflated or len(inflated) < 72:
        return info

    # Solid mode: first 4 bytes of decompressed data = header size
    hdr_size = struct.unpack_from("<I", inflated, 0)[0]
    if 100 < hdr_size < len(inflated):
        inflated = inflated[4:hdr_size + 4]

    # Parse header: common_header (68 bytes) then block headers
    # Common header layout varies by version, but block headers start at offset 68
    # Header: flags(4) + blocks_raw(8*8=64)
    # Actually: common_flags(4) + install_reg_rootkey(4) + ... complex
    # Skip to block headers at offset 0 of the header data
    # The header format has blocks at a fixed offset after the common fields.
    # For simplicity, parse blocks starting from a known offset.
    # NSIS3: header is 292 bytes of common data + block headers

    # Try to detect NSIS version from string block content
    # NSIS3 Unicode: strings are UTF-16LE
    # NSIS2: strings are ASCII with high-byte escapes

    # Parse block headers (8 blocks, each 8 bytes: offset + num_items)
    # Block headers start after common_header (varies by version)
    # Typical offset for NSIS3: after 68 bytes of common data
    # We'll try multiple offsets
    blocks = []
    block_header_offset = -1

    for try_offset in [68, 60, 72, 56, 80, 64]:
        candidate_blocks = []
        valid = True
        for i in range(_BLOCKS_COUNT):
            bh_pos = try_offset + i * _BH_STRUCT.size
            if bh_pos + _BH_STRUCT.size > len(inflated):
                valid = False
                break
            offset, num = _BH_STRUCT.unpack_from(inflated, bh_pos)
            if offset > len(inflated) or num > 1000000:
                valid = False
                break
            candidate_blocks.append((offset, num))
        if valid and len(candidate_blocks) == _BLOCKS_COUNT:
            # Validate: strings block offset should point to readable data
            str_off, str_num = candidate_blocks[NB_STRINGS]
            if str_off > 0 and str_off < len(inflated):
                blocks = candidate_blocks
                block_header_offset = try_offset
                break

    if not blocks:
        # Fallback: just extract all strings from inflated data
        # Try UTF-16LE first (NSIS3)
        utf16_strings = re.findall(rb"(?:[\x20-\x7e]\x00){4,}", inflated)
        if utf16_strings:
            info.unicode = True
            info.version = 3
            for s in utf16_strings:
                decoded = s.decode("utf-16-le", errors="replace").strip()
                if decoded and len(decoded) > 2:
                    info.strings.append(decoded)
        else:
            # Try ASCII (NSIS2)
            info.unicode = False
            info.version = 2
            ascii_strings = re.findall(rb"[\x20-\x7e]{4,}", inflated)
            for s in ascii_strings:
                decoded = s.decode("ascii", errors="replace").strip()
                if decoded:
                    info.strings.append(decoded)
        info.num_strings = len(info.strings)
        return info

    # Extract strings block
    str_offset, _ = blocks[NB_STRINGS]
    str_block = inflated[str_offset:]

    # Detect Unicode vs ANSI
    # If the first few bytes have alternating zero bytes, it's UTF-16LE
    sample = str_block[:100]
    zero_count = sum(1 for b in sample[1::2] if b == 0)
    if zero_count > len(sample) // 4:
        info.unicode = True
        info.version = 3
        info.strings = _extract_strings_nsis3(str_block)
    else:
        info.unicode = False
        info.version = 2
        info.strings = _extract_strings_nsis2(str_block)

    info.num_strings = len(info.strings)

    # Extract entries block
    ent_offset, ent_num = blocks[NB_ENTRIES]
    if ent_offset > 0 and ent_num > 0 and ent_num < 100000:
        info.num_entries = ent_num
        ent_block = inflated[ent_offset:]
        for i in range(min(ent_num, 10000)):
            pos = i * _ENTRY_STRUCT.size
            if pos + _ENTRY_STRUCT.size > len(ent_block):
                break
            vals = _ENTRY_STRUCT.unpack_from(ent_block, pos)
            opcode = vals[0]
            params = vals[1:]
            op_name = _OPCODES.get(opcode, f"op_{opcode}")
            info.entries.append((op_name, list(params)))

    # Extract sections
    sec_offset, sec_num = blocks[NB_SECTIONS]
    if sec_num > 0 and sec_num < 1000:
        info.sections = [f"Section_{i}" for i in range(sec_num)]

    return info
