"""
Sliding-window entropy analysis for identifying packed/encrypted regions.

Uses numpy for fast computation when available, falls back to pure Python.
"""
from __future__ import annotations

import math
from typing import Optional

try:
    import numpy as np
    _HAS_NUMPY = True
except ImportError:
    np = None  # type: ignore[assignment]
    _HAS_NUMPY = False


def section_entropy(data: bytes) -> float:
    """Compute Shannon entropy (bits per byte) for *data*.

    Returns a value in [0.0, 8.0].  Perfectly random data ~ 8.0,
    all-zero data = 0.0.
    """
    if not data:
        return 0.0

    if _HAS_NUMPY:
        arr = np.frombuffer(data, dtype=np.uint8)
        counts = np.bincount(arr, minlength=256).astype(np.float64)
        probs = counts / len(arr)
        # mask zeros to avoid log2(0)
        nonzero = probs > 0
        return float(-np.sum(probs[nonzero] * np.log2(probs[nonzero])))

    # Pure Python fallback
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    length = len(data)
    ent = 0.0
    for c in freq:
        if c:
            p = c / length
            ent -= p * math.log2(p)
    return ent


def entropy_map(data: bytes, window: int = 256, step: int = 64) -> list[tuple[int, float]]:
    """Compute entropy at each sliding window position.

    Returns list of (offset, entropy) pairs.
    """
    if not data or window <= 0:
        return []

    results: list[tuple[int, float]] = []

    if _HAS_NUMPY and len(data) >= window:
        arr = np.frombuffer(data, dtype=np.uint8)

        # Initial histogram for first window
        counts = np.bincount(arr[:window], minlength=256).astype(np.float64)
        offset = 0
        while offset + window <= len(arr):
            if offset > 0:
                # Slide: remove old byte, add new byte
                old_start = offset - step
                new_start = offset
                # Recompute from scratch at each step for correctness
                # (incremental update across variable step is error-prone)
                counts = np.bincount(arr[offset:offset + window], minlength=256).astype(np.float64)

            probs = counts / window
            nonzero = probs > 0
            ent = float(-np.sum(probs[nonzero] * np.log2(probs[nonzero])))
            results.append((offset, ent))
            offset += step

        return results

    # Pure Python
    offset = 0
    while offset + window <= len(data):
        chunk = data[offset : offset + window]
        results.append((offset, section_entropy(chunk)))
        offset += step
    return results


def find_high_entropy_regions(
    data: bytes, threshold: float = 7.0, window: int = 256, step: int = 64
) -> list[tuple[int, int]]:
    """Find contiguous regions where entropy exceeds *threshold*.

    Returns list of (start_offset, end_offset) pairs.
    """
    emap = entropy_map(data, window=window, step=step)
    if not emap:
        return []

    regions: list[tuple[int, int]] = []
    region_start: Optional[int] = None

    for offset, ent in emap:
        if ent >= threshold:
            if region_start is None:
                region_start = offset
        else:
            if region_start is not None:
                regions.append((region_start, offset))
                region_start = None

    # Close trailing region
    if region_start is not None:
        last_offset = emap[-1][0]
        regions.append((region_start, last_offset + window))

    # Merge adjacent/overlapping regions
    if len(regions) <= 1:
        return regions

    merged: list[tuple[int, int]] = [regions[0]]
    for start, end in regions[1:]:
        prev_start, prev_end = merged[-1]
        if start <= prev_end:
            merged[-1] = (prev_start, max(prev_end, end))
        else:
            merged.append((start, end))

    return merged
