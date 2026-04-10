"""
XOR decryption utilities — frequency analysis, Kasiski, and auto-detection.
"""
from __future__ import annotations

import math
from collections import Counter


def single_byte_xor(data: bytes) -> tuple[int, bytes]:
    """Crack single-byte XOR via frequency analysis.

    The most frequent byte in the ciphertext is assumed to be the XOR of
    the key with 0x00 (null byte) — which is very common in binary data
    and PE padding.

    Returns (key_byte, decrypted_data).
    """
    if not data:
        return (0, b"")

    freq = Counter(data)
    # Most common byte XOR 0x00 = key
    most_common_byte = freq.most_common(1)[0][0]
    key = most_common_byte ^ 0x00

    decrypted = bytes(b ^ key for b in data)
    return (key, decrypted)


def multi_byte_xor(data: bytes, key_len: int) -> tuple[bytes, bytes]:
    """Crack multi-byte XOR by applying single-byte frequency analysis
    per key position (stride).

    Returns (key, decrypted_data).
    """
    if not data or key_len <= 0:
        return (b"", data or b"")

    key_bytes: list[int] = []
    for pos in range(key_len):
        # Extract every key_len-th byte starting at offset `pos`
        stripe = data[pos::key_len]
        k, _ = single_byte_xor(stripe)
        key_bytes.append(k)

    key = bytes(key_bytes)
    decrypted = bytearray(len(data))
    for i, b in enumerate(data):
        decrypted[i] = b ^ key_bytes[i % key_len]

    return (key, bytes(decrypted))


def detect_xor_key_length(data: bytes, max_len: int = 32) -> int:
    """Estimate the XOR key length using Index of Coincidence (IoC) analysis.

    Similar to Kasiski examination: for each candidate key length, compute
    the average IoC across all byte strides.  The length with the highest
    average IoC (closest to natural data distribution) is the best guess.

    Returns the estimated key length (1..max_len).
    """
    if not data or max_len < 1:
        return 1

    best_len = 1
    best_ioc = -1.0

    for kl in range(1, min(max_len, len(data)) + 1):
        total_ioc = 0.0
        stripes = 0
        for pos in range(kl):
            stripe = data[pos::kl]
            ioc = _index_of_coincidence(stripe)
            total_ioc += ioc
            stripes += 1
        avg_ioc = total_ioc / stripes if stripes > 0 else 0.0
        if avg_ioc > best_ioc:
            best_ioc = avg_ioc
            best_len = kl

    return best_len


def auto_xor(data: bytes) -> tuple[bytes, bytes, str]:
    """Automatically try single-byte and multi-byte XOR decryption.

    Returns (key, decrypted_data, method_description).

    Strategy:
    1. Try single-byte XOR first.
    2. If the decrypted data looks reasonable (has printable ratio > 30%
       or starts with a known magic), accept it.
    3. Otherwise, detect key length and try multi-byte XOR.
    """
    if not data:
        return (b"", b"", "empty")

    # --- Single byte ---
    key1, dec1 = single_byte_xor(data)
    if key1 == 0:
        # No encryption (key=0 means XOR with 0 = identity)
        return (bytes([0]), data, "none (key=0x00)")

    if _looks_reasonable(dec1):
        return (bytes([key1]), dec1, f"single-byte (key=0x{key1:02x})")

    # --- Multi byte ---
    key_len = detect_xor_key_length(data, max_len=32)
    if key_len <= 1:
        # Fall back to single-byte result
        return (bytes([key1]), dec1, f"single-byte (key=0x{key1:02x})")

    key_m, dec_m = multi_byte_xor(data, key_len)

    if _looks_reasonable(dec_m):
        return (key_m, dec_m, f"multi-byte (key_len={key_len}, key={key_m.hex()})")

    # Return the multi-byte result anyway — caller decides
    return (key_m, dec_m, f"multi-byte-uncertain (key_len={key_len}, key={key_m.hex()})")


# ------------------------------------------------------------------
# Internal helpers
# ------------------------------------------------------------------

def _index_of_coincidence(data: bytes) -> float:
    """Compute the Index of Coincidence for a byte sequence."""
    n = len(data)
    if n <= 1:
        return 0.0
    freq = Counter(data)
    total = sum(c * (c - 1) for c in freq.values())
    return total / (n * (n - 1))


_KNOWN_MAGICS = [b"MZ", b"\x7fELF", b"PK", b"\x89PNG", b"GIF8"]


def _looks_reasonable(data: bytes) -> bool:
    """Heuristic check: does decrypted data look like valid content?"""
    if len(data) < 4:
        return False

    # Check known magic bytes
    for magic in _KNOWN_MAGICS:
        if data[:len(magic)] == magic:
            return True

    # Check printable ratio (printable ASCII + common whitespace)
    printable = sum(1 for b in data[:1024] if 0x20 <= b <= 0x7E or b in (0x09, 0x0A, 0x0D, 0x00))
    ratio = printable / min(len(data), 1024)
    return ratio > 0.30
