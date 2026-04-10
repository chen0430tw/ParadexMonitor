"""
Common encoding detection and decoding — base64, base32, hex, percent-encoding.
"""
from __future__ import annotations

import base64
import binascii
import re
import string
from urllib.parse import unquote_to_bytes


# Characters valid in standard base64 (with padding)
_B64_CHARS = set(string.ascii_letters + string.digits + "+/=\r\n ")
# Characters valid in base32
_B32_CHARS = set(string.ascii_uppercase + "234567=\r\n ")
# Characters valid in hex
_HEX_CHARS = set(string.hexdigits + " \r\n")
# Percent-encoding pattern
_PCT_RE = re.compile(rb"(?:%[0-9A-Fa-f]{2}){3,}")


def detect_encoding(data: bytes) -> str:
    """Detect the most likely encoding of *data*.

    Returns one of: "base64", "base32", "hex", "percent", "raw".
    """
    if not data:
        return "raw"

    # Try to decode as text for pattern matching
    try:
        text = data.decode("ascii")
    except (UnicodeDecodeError, ValueError):
        # Binary data with non-ASCII bytes -> check percent-encoding in raw
        if _PCT_RE.search(data):
            return "percent"
        return "raw"

    stripped = text.strip()
    if not stripped:
        return "raw"

    # Percent-encoding: at least 3 consecutive %XX sequences
    if _PCT_RE.search(data):
        return "percent"

    # Hex: all hex chars, even length (ignoring whitespace)
    hex_clean = stripped.replace(" ", "").replace("\n", "").replace("\r", "")
    if len(hex_clean) >= 2 and len(hex_clean) % 2 == 0 and all(c in string.hexdigits for c in hex_clean):
        return "hex"

    # Base32: uppercase + 2-7 + padding, length divisible by 8
    b32_clean = stripped.replace(" ", "").replace("\n", "").replace("\r", "")
    if (len(b32_clean) >= 8
            and len(b32_clean) % 8 == 0
            and all(c in _B32_CHARS for c in stripped)):
        try:
            base64.b32decode(b32_clean)
            return "base32"
        except Exception:
            pass

    # Base64: mixed case + digits + +/= , length divisible by 4
    b64_clean = stripped.replace(" ", "").replace("\n", "").replace("\r", "")
    if (len(b64_clean) >= 4
            and len(b64_clean) % 4 == 0
            and all(c in _B64_CHARS for c in stripped)):
        try:
            base64.b64decode(b64_clean, validate=True)
            return "base64"
        except Exception:
            pass

    return "raw"


def decode(data: bytes, encoding: str | None = None) -> bytes:
    """Decode *data* using the specified or auto-detected encoding.

    Returns the decoded bytes.  For "raw", returns *data* unchanged.
    """
    if encoding is None:
        encoding = detect_encoding(data)

    if encoding == "base64":
        try:
            # Strip whitespace before decoding
            clean = data.replace(b"\r", b"").replace(b"\n", b"").replace(b" ", b"")
            return base64.b64decode(clean, validate=True)
        except Exception:
            return data

    if encoding == "base32":
        try:
            clean = data.replace(b"\r", b"").replace(b"\n", b"").replace(b" ", b"")
            return base64.b32decode(clean)
        except Exception:
            return data

    if encoding == "hex":
        try:
            clean = data.replace(b" ", b"").replace(b"\r", b"").replace(b"\n", b"")
            return binascii.unhexlify(clean)
        except Exception:
            return data

    if encoding == "percent":
        try:
            return unquote_to_bytes(data)
        except Exception:
            return data

    # raw / unknown
    return data
