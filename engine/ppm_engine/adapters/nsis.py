"""
NSIS (Nullsoft Scriptable Install System) adapter -- parse NSIS installer/uninstaller packages.

Extracts:
- NSIS version (2 or 3, Unicode or ANSI, Park variants)
- Compression method (LZMA, Zlib, Bzip2)
- String table with variable/shell/language code expansion
- Script entries (bytecode opcodes with correct NumParams)
- Embedded files list

Reference: NSIS source code (nsis.sourceforge.io)
Observer NSIS module (github.com/lazyhamster/Observer) — opcode table, variable codes
nrs (NSIS Reversing Suite) — header decompression
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

# ── NSIS opcodes (from Observer NsisIn.cpp EW_* enum) ─────────────────────────
# (name, num_params) — num_params from Observer k_Commands[] table
_OPCODES = [
    ("Invalid", 0),           # 0
    ("Return", 0),            # 1
    ("Nop", 1),               # 2
    ("Abort", 1),             # 3
    ("Quit", 0),              # 4
    ("Call", 2),              # 5
    ("UpdateText", 6),        # 6
    ("Sleep", 1),             # 7
    ("BringToFront", 0),      # 8
    ("ChDir", 2),             # 9
    ("SetFileAttributes", 2), # 10
    ("CreateDir", 2),         # 11
    ("IfFileExists", 3),      # 12
    ("SetFlag", 2),           # 13
    ("IfFlag", 4),            # 14
    ("GetFlag", 2),           # 15
    ("Rename", 3),            # 16
    ("GetFullPathName", 3),   # 17
    ("SearchPath", 2),        # 18
    ("GetTempFileName", 2),   # 19
    ("ExtractFile", 6),       # 20
    ("DeleteFile", 2),        # 21
    ("MessageBox", 5),        # 22
    ("RMDir", 2),             # 23
    ("StrLen", 2),            # 24
    ("AssignVar", 4),         # 25
    ("StrCmp", 5),            # 26
    ("ReadEnvStr", 3),        # 27
    ("IntCmp", 6),            # 28
    ("IntOp", 4),             # 29
    ("IntFmt", 4),            # 30
    ("PushPop", 6),           # 31
    ("FindWindow", 5),        # 32
    ("SendMessage", 6),       # 33
    ("IsWindow", 3),          # 34
    ("GetDlgItem", 3),        # 35
    ("SetCtlColors", 3),      # 36
    ("SetBrandingImage", 4),  # 37
    ("CreateFont", 5),        # 38
    ("ShowWindow", 4),        # 39
    ("ShellExec", 6),         # 40
    ("Execute", 3),           # 41
    ("GetFileTime", 3),       # 42
    ("GetDLLVersion", 4),     # 43
    ("RegisterDLL", 6),       # 44  (also Plugin call)
    ("CreateShortcut", 6),    # 45
    ("CopyFiles", 4),         # 46
    ("Reboot", 1),            # 47
    ("WriteINI", 4),          # 48
    ("ReadINIStr", 4),        # 49
    ("DeleteINISec", 3),      # 50
    ("DeleteINIStr", 3),      # 51  (also FlushINI)
    ("FindFirst", 3),         # 52
    ("FindNext", 2),          # 53
    ("FindClose", 1),         # 54
    ("FileOpen", 4),          # 55
    ("FileClose", 1),         # 56
    ("FileSeek", 4),          # 57
    ("FileRead", 4),          # 58
    ("FileWrite", 3),         # 59
    ("FileReadByte", 3),      # 60
    ("FileWriteByte", 2),     # 61
    ("FileReadUTF16LE", 4),   # 62
    ("FileWriteUTF16LE", 3),  # 63
    ("FileReadWord", 3),      # 64
    ("FileWriteWord", 2),     # 65
    ("GetOSInfo", 6),         # 66
    ("SetDetailsView", 1),    # 67
    ("SetDetailsPrint", 1),   # 68
    ("SetAutoClose", 1),      # 69
    ("SetOverwrite", 1),      # 70
    ("SetDatablockOpt", 1),   # 71
    ("SetDateSave", 1),       # 72
    ("WriteUninstaller", 4),  # 73
    ("SetRegView", 2),        # 74  (also Log)
    ("GetLabelAddress", 2),   # 75
    ("GetCurrentAddress", 1), # 76
    ("SectionSetFlags", 2),   # 77
    ("SectionGetFlags", 2),   # 78
    ("SectionSetText", 2),    # 79
    ("SectionGetText", 2),    # 80
    ("GetCurrentInstType", 1),# 81
    ("SetCurInstType", 1),    # 82
    ("GetLabelAddr2", 2),     # 83  (also SetShellVarContext)
    ("GetFunctionAddr", 2),   # 84
    ("LockWindow", 1),        # 85
    ("FindProc", 2),          # 86  (NSIS 3.08+)
]

# Build lookup dict
_OP_DICT = {i: (name, nparams) for i, (name, nparams) in enumerate(_OPCODES)}

# ── NSIS variable names (from Observer) ───────────────────────────────────────
# NSIS3 variable codes: 0x00=skip, 0x01=var, 0x02=shell, 0x03=lang, 0x04=skip2
# NSIS2 variable codes: 0xFD=var, 0xFE=shell, 0xFF=lang
_NSIS_VARS = {
    0:  "$0",  1:  "$1",  2:  "$2",  3:  "$3",  4:  "$4",
    5:  "$5",  6:  "$6",  7:  "$7",  8:  "$8",  9:  "$9",
    10: "$R0", 11: "$R1", 12: "$R2", 13: "$R3", 14: "$R4",
    15: "$R5", 16: "$R6", 17: "$R7", 18: "$R8", 19: "$R9",
    20: "$CMDLINE",
    21: "$INSTDIR",
    22: "$OUTDIR",
    23: "$EXEDIR",
    24: "$LANGUAGE",
    25: "$TEMP",
    26: "$PLUGINSDIR",
    27: "$EXEPATH",
    28: "$EXEFILE",
    29: "$HWNDPARENT",
    30: "$_CLICK",
    31: "$_OUTDIR",
}

_SHELL_VARS = {
    0:  "$DESKTOP",    1:  "$SMPROGRAMS",   2:  "$SMSTARTUP",
    3:  "$STARTMENU",  4:  "$MYMUSIC",      5:  "$MYVIDEO",
    6:  "$INSTDIR_",   7:  "$PROGRAMFILES",  8:  "$SYSDIR",
    9:  "$WINDIR",     10: "$FONTS",         11: "$SENDTO",
    12: "$RECENT",     13: "$FAVORITES",     14: "$MUSIC",
    15: "$PICTURES",   16: "$VIDEOS",        17: "$NETHOOD",
    18: "$PRINTHOOD",  19: "$INTERNET_CACHE",20: "$COOKIES",
    21: "$HISTORY",    22: "$PROFILE",       23: "$ADMINTOOLS",
    24: "$RESOURCES",  25: "$RESOURCES_LOCALIZED",
    26: "$CDBURN_AREA",27: "$COMMONFILES",   28: "$APPDATA",
    29: "$LOCALAPPDATA",30: "$DOCUMENTS",    31: "$COMMONDOCUMENTS",
    32: "$COMMONDESKTOP", 33: "$QUICKLAUNCH",
}

# ── Struct definitions ────────────────────────────────────────────────────────
_FH_STRUCT = struct.Struct("<I I 12s I I")  # 28 bytes
_BH_STRUCT = struct.Struct("<I I")           # 8 bytes
_ENTRY_STRUCT = struct.Struct("<I 6I")       # 28 bytes


@dataclass
class NSISInfo:
    """Parsed NSIS installer information."""
    version: int = 3            # 2 or 3
    unicode: bool = True
    is_uninstaller: bool = False
    compression: str = "unknown"
    strings: list = field(default_factory=list)
    entries: list = field(default_factory=list)
    sections: list = field(default_factory=list)
    num_entries: int = 0
    num_strings: int = 0
    stub_size: int = 0
    header_size: int = 0


def is_nsis(data: bytes) -> bool:
    """Quick check: does this PE contain an NSIS firstheader?"""
    return _find_firstheader_offset(data) is not None


def _find_firstheader_offset(data: bytes) -> Optional[int]:
    """Scan for NullsoftInst + DEADBEEF signature."""
    search_limit = min(len(data), 1024 * 1024)
    idx = 0
    while idx < search_limit:
        pos = data.find(_FH_MAGIC, idx, search_limit)
        if pos == -1:
            return None
        fh_start = pos - 8
        if fh_start < 0:
            idx = pos + 1
            continue
        sig = struct.unpack_from("<I", data, fh_start + 4)[0]
        if sig == _FH_SIG:
            return fh_start
        idx = pos + 1
    return None


def _detect_compression(data: bytes) -> str:
    if len(data) < 6:
        return "unknown"
    if data[0:3] == bytes([0x5D, 0, 0]) and data[5] == 0:
        return "lzma"
    if data[0] <= 1 and data[1] == 0x5D and data[2] == 0 and data[3] == 0:
        return "lzma"
    if data[0] == 0x31 and data[1] < 0x0E:
        return "bzip2"
    return "zlib"


def _decompress(data: bytes, method: str) -> bytes:
    if method == "lzma":
        import lzma
        offset = 0
        if data[0] <= 1 and data[1] == 0x5D:
            offset = 1
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


# ── String extraction with variable code expansion ───────────────────────────

def _expand_nsis3_codes(raw: str) -> str:
    """Expand NSIS3 variable/shell/lang codes in a string."""
    result = []
    i = 0
    while i < len(raw):
        c = ord(raw[i])
        if c == 0x01 and i + 1 < len(raw):
            # NS_3_CODE_VAR: next char is variable index
            var_idx = ord(raw[i + 1])
            result.append(_NSIS_VARS.get(var_idx, f"$var{var_idx}"))
            i += 2
        elif c == 0x02 and i + 1 < len(raw):
            # NS_3_CODE_SHELL: next char is shell folder index
            shell_idx = ord(raw[i + 1])
            result.append(_SHELL_VARS.get(shell_idx, f"$shell{shell_idx}"))
            i += 2
        elif c == 0x03 and i + 1 < len(raw):
            # NS_3_CODE_LANG: next char is language string index
            lang_idx = ord(raw[i + 1])
            result.append(f"$(LangString_{lang_idx})")
            i += 2
        elif c == 0x04:
            # NS_3_CODE_SKIP
            i += 1
        else:
            result.append(raw[i])
            i += 1
    return "".join(result)


def _expand_nsis2_codes(raw: str) -> str:
    """Expand NSIS2 variable/shell/lang codes (0xFD/0xFE/0xFF)."""
    result = []
    i = 0
    while i < len(raw):
        c = ord(raw[i])
        if c == 0xFD and i + 1 < len(raw):
            var_idx = ord(raw[i + 1])
            result.append(_NSIS_VARS.get(var_idx, f"$var{var_idx}"))
            i += 2
        elif c == 0xFE and i + 1 < len(raw):
            shell_idx = ord(raw[i + 1])
            result.append(_SHELL_VARS.get(shell_idx, f"$shell{shell_idx}"))
            i += 2
        elif c == 0xFF and i + 1 < len(raw):
            lang_idx = ord(raw[i + 1])
            result.append(f"$(LangString_{lang_idx})")
            i += 2
        else:
            result.append(raw[i])
            i += 1
    return "".join(result)


def _extract_strings_nsis3(block: bytes) -> list[str]:
    """Extract null-terminated UTF-16LE strings from NSIS3 string block."""
    strings = []
    i = 0
    while i < len(block) - 1:
        end = i
        while end < len(block) - 1:
            if block[end] == 0 and block[end + 1] == 0:
                break
            end += 2
        if end > i:
            try:
                raw = block[i:end].decode("utf-16-le", errors="replace")
                expanded = _expand_nsis3_codes(raw)
                if expanded:
                    strings.append(expanded)
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
                raw = block[i:end].decode("ascii", errors="replace")
                expanded = _expand_nsis2_codes(raw)
                if expanded:
                    strings.append(expanded)
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

    flags, sig, magic, comp_size, decomp_size = _FH_STRUCT.unpack_from(data, fh_offset)
    info.is_uninstaller = bool(flags & 1)
    info.header_size = comp_size

    data_offset = fh_offset + _FH_STRUCT.size
    compressed = data[data_offset:]

    # Decompress: try solid then non-solid, all methods
    inflated = b""
    for try_offset in [0, 4]:
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

    # Solid: first 4 bytes = header size
    hdr_size = struct.unpack_from("<I", inflated, 0)[0]
    if 100 < hdr_size < len(inflated):
        inflated = inflated[4:hdr_size + 4]

    # Block headers at offset 4 (after flags DWORD)
    blocks = []
    for i in range(_BLOCKS_COUNT):
        bh_pos = 4 + i * _BH_STRUCT.size
        if bh_pos + _BH_STRUCT.size > len(inflated):
            break
        offset, num = _BH_STRUCT.unpack_from(inflated, bh_pos)
        blocks.append((offset, num))

    if len(blocks) == _BLOCKS_COUNT:
        str_off, _ = blocks[NB_STRINGS]
        if str_off == 0 or str_off >= len(inflated):
            blocks = []

    if not blocks:
        # Fallback: regex extraction
        utf16_strings = re.findall(rb"(?:[\x20-\x7e]\x00){4,}", inflated)
        if utf16_strings:
            info.unicode = True
            info.version = 3
            for s in utf16_strings:
                decoded = s.decode("utf-16-le", errors="replace").strip()
                if decoded and len(decoded) > 2:
                    info.strings.append(decoded)
        else:
            info.unicode = False
            info.version = 2
            for s in re.findall(rb"[\x20-\x7e]{4,}", inflated):
                decoded = s.decode("ascii", errors="replace").strip()
                if decoded:
                    info.strings.append(decoded)
        info.num_strings = len(info.strings)
        return info

    # ── Extract strings with variable expansion ───────────────────────────
    str_offset, _ = blocks[NB_STRINGS]
    str_block = inflated[str_offset:]

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

    # ── Extract entries with correct NumParams ────────────────────────────
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
            all_params = list(vals[1:])

            op_name, num_params = _OP_DICT.get(opcode, (f"op_{opcode}", 6))
            # Trim trailing zero params to num_params
            params = all_params[:num_params] if num_params < 6 else all_params
            # Further trim trailing zeros
            while params and params[-1] == 0:
                params.pop()

            info.entries.append((op_name, params))

    # ── Extract sections ──────────────────────────────────────────────────
    sec_offset, sec_num = blocks[NB_SECTIONS]
    if sec_num > 0 and sec_num < 1000:
        info.sections = [f"Section_{i}" for i in range(sec_num)]

    return info
