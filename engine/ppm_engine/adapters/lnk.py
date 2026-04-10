"""
LNK (Windows Shell Link) adapter -- parse .lnk shortcut files.

Extracts target path, arguments, working directory, icon location,
and flags. Useful for detecting malicious shortcuts (PowerShell
downloaders, LOLBin abuse, etc.)

Reference: MS-SHLLINK specification
https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-shllink
"""
from __future__ import annotations

import struct
from pathlib import Path


# Shell Link header magic: 4C 00 00 00
_LNK_MAGIC = b"\x4c\x00\x00\x00"
# CLSID: 00021401-0000-0000-C000-000000000046
_LNK_CLSID = (
    b"\x01\x14\x02\x00\x00\x00\x00\x00"
    b"\xc0\x00\x00\x00\x00\x00\x00\x46"
)

# LinkFlags bit positions
_HAS_LINK_TARGET_ID_LIST = 0x00000001
_HAS_LINK_INFO = 0x00000002
_HAS_NAME = 0x00000004
_HAS_RELATIVE_PATH = 0x00000008
_HAS_WORKING_DIR = 0x00000010
_HAS_ARGUMENTS = 0x00000020
_HAS_ICON_LOCATION = 0x00000040

# Suspicious patterns in LNK arguments/targets
_SUSPICIOUS_COMMANDS = [
    "powershell", "pwsh", "cmd.exe", "mshta", "wscript", "cscript",
    "certutil", "bitsadmin", "regsvr32", "rundll32", "msiexec",
    "forfiles", "pcalua", "schtasks",
]

_SUSPICIOUS_PATTERNS = [
    "-enc", "-encodedcommand", "-e ", "frombase64",
    "downloadstring", "downloadfile", "invoke-expression", "iex ",
    "invoke-webrequest", "iwr ", "start-bitstransfer",
    "http://", "https://", "ftp://",
    "bypass", "-nop", "-noprofile", "-w hidden", "-windowstyle hidden",
    "&&", "||", "|", ";",
]


class LNKAdapter:
    """Parse a Windows .lnk shortcut file."""

    def __init__(self, path: str) -> None:
        self.path = path
        with open(path, "rb") as f:
            self._raw = f.read()

        if len(self._raw) < 76:
            raise ValueError(f"File too small for LNK: {len(self._raw)} bytes")
        if self._raw[:4] != _LNK_MAGIC:
            raise ValueError(f"Not a LNK file (bad magic): {self._raw[:4].hex()}")

        self._parse_header()
        self._parse_body()

    def _parse_header(self) -> None:
        """Parse the 76-byte ShellLinkHeader."""
        # Bytes 0-3: HeaderSize (always 0x4C)
        # Bytes 4-19: LinkCLSID
        # Bytes 20-23: LinkFlags
        # Bytes 24-27: FileAttributes
        # Bytes 28-35: CreationTime (FILETIME)
        # Bytes 36-43: AccessTime
        # Bytes 44-51: WriteTime
        # Bytes 52-55: FileSize
        # Bytes 56-59: IconIndex
        # Bytes 60-63: ShowCommand
        # Bytes 64-65: HotKey
        self.link_flags = struct.unpack_from("<I", self._raw, 20)[0]
        self.file_attributes = struct.unpack_from("<I", self._raw, 24)[0]
        self.file_size = struct.unpack_from("<I", self._raw, 52)[0]
        self.icon_index = struct.unpack_from("<i", self._raw, 56)[0]
        self.show_command = struct.unpack_from("<I", self._raw, 60)[0]

    def _parse_body(self) -> None:
        """Parse LinkTargetIDList, LinkInfo, and StringData."""
        offset = 76  # after header

        self.target_id_list: list[bytes] = []
        self.local_base_path: str = ""
        self.description: str = ""
        self.relative_path: str = ""
        self.working_dir: str = ""
        self.arguments: str = ""
        self.icon_location: str = ""

        # LinkTargetIDList
        if self.link_flags & _HAS_LINK_TARGET_ID_LIST:
            if offset + 2 <= len(self._raw):
                id_list_size = struct.unpack_from("<H", self._raw, offset)[0]
                offset += 2 + id_list_size

        # LinkInfo
        if self.link_flags & _HAS_LINK_INFO:
            if offset + 4 <= len(self._raw):
                link_info_size = struct.unpack_from("<I", self._raw, offset)[0]
                link_info_data = self._raw[offset:offset + link_info_size]
                self._parse_link_info(link_info_data)
                offset += link_info_size

        # StringData sections (each: uint16 count + count*2 bytes UTF-16LE)
        if self.link_flags & _HAS_NAME:
            self.description, offset = self._read_string_data(offset)
        if self.link_flags & _HAS_RELATIVE_PATH:
            self.relative_path, offset = self._read_string_data(offset)
        if self.link_flags & _HAS_WORKING_DIR:
            self.working_dir, offset = self._read_string_data(offset)
        if self.link_flags & _HAS_ARGUMENTS:
            self.arguments, offset = self._read_string_data(offset)
        if self.link_flags & _HAS_ICON_LOCATION:
            self.icon_location, offset = self._read_string_data(offset)

    def _parse_link_info(self, data: bytes) -> None:
        """Parse LinkInfo structure to extract LocalBasePath."""
        if len(data) < 28:
            return
        link_info_flags = struct.unpack_from("<I", data, 8)[0]
        # VolumeIDAndLocalBasePath flag
        if link_info_flags & 0x01:
            local_base_path_offset = struct.unpack_from("<I", data, 16)[0]
            if local_base_path_offset < len(data):
                end = data.index(b"\x00", local_base_path_offset) if b"\x00" in data[local_base_path_offset:] else len(data)
                self.local_base_path = data[local_base_path_offset:end].decode("ascii", errors="replace")

    def _read_string_data(self, offset: int) -> tuple[str, int]:
        """Read a StringData entry (uint16 char count + UTF-16LE chars)."""
        if offset + 2 > len(self._raw):
            return "", offset
        count = struct.unpack_from("<H", self._raw, offset)[0]
        offset += 2
        byte_len = count * 2
        if offset + byte_len > len(self._raw):
            return "", offset
        text = self._raw[offset:offset + byte_len].decode("utf-16-le", errors="replace")
        return text, offset + byte_len

    # ------------------------------------------------------------------
    # Public API (matching adapter interface where applicable)
    # ------------------------------------------------------------------

    def target(self) -> str:
        """Return the resolved target path."""
        return self.local_base_path or self.relative_path or ""

    def summary(self) -> dict:
        """Return a structured summary of the shortcut."""
        return {
            "target": self.target(),
            "arguments": self.arguments,
            "working_dir": self.working_dir,
            "description": self.description,
            "icon_location": self.icon_location,
            "icon_index": self.icon_index,
            "file_size": self.file_size,
            "show_command": self._show_command_str(),
        }

    def analyze_risk(self) -> dict:
        """Analyze the shortcut for suspicious patterns.

        Returns a dict with risk score, indicators, and classification.
        """
        indicators: list[str] = []
        risk = 0.0

        target_lower = self.target().lower()
        args_lower = self.arguments.lower()
        combined = f"{target_lower} {args_lower}"

        # Check target binary
        for cmd in _SUSPICIOUS_COMMANDS:
            if cmd in target_lower:
                risk += 0.3
                indicators.append(f"Target is LOLBin: {cmd}")
                break

        # Check arguments for suspicious patterns
        for pat in _SUSPICIOUS_PATTERNS:
            if pat in args_lower:
                risk += 0.15
                indicators.append(f"Suspicious argument pattern: {pat.strip()}")

        # Hidden window
        if self.show_command == 7:  # SW_SHOWMINNOACTIVE
            risk += 0.1
            indicators.append("Window starts minimized (hidden)")
        elif self.show_command == 0:  # SW_HIDE
            risk += 0.2
            indicators.append("Window is hidden (SW_HIDE)")

        # Very long arguments (obfuscation)
        if len(self.arguments) > 500:
            risk += 0.15
            indicators.append(f"Unusually long arguments ({len(self.arguments)} chars)")

        # Base64-looking content
        if any(x in args_lower for x in ["-enc", "-encodedcommand", "frombase64"]):
            risk += 0.2
            indicators.append("Base64-encoded command detected")

        risk = round(min(risk, 1.0), 2)

        if risk >= 0.7:
            classification = "highly_suspicious"
        elif risk >= 0.4:
            classification = "suspicious"
        elif risk >= 0.2:
            classification = "unusual"
        else:
            classification = "benign"

        return {
            "risk": risk,
            "classification": classification,
            "indicators": indicators,
            "target": self.target(),
            "arguments": self.arguments[:200] + ("..." if len(self.arguments) > 200 else ""),
        }

    def strings(self, min_len: int = 6) -> list[dict]:
        """Extract strings from the LNK (target, args, paths, etc.)."""
        results: list[dict] = []
        for field_name in ("local_base_path", "arguments", "working_dir",
                           "description", "relative_path", "icon_location"):
            val = getattr(self, field_name, "")
            if val and len(val) >= min_len:
                results.append({
                    "rva": 0,
                    "encoding": "utf-16-le",
                    "value": val,
                    "field": field_name,
                })
        return results

    def _show_command_str(self) -> str:
        return {0: "SW_HIDE", 1: "SW_NORMAL", 3: "SW_MAXIMIZED",
                7: "SW_SHOWMINNOACTIVE"}.get(self.show_command, f"0x{self.show_command:X}")
