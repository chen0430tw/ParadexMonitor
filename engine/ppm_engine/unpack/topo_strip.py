"""
Topology-based packer/payload separation.

Classify PE sections as either 'envelope' (packer stub) or 'payload'
(original code) by analyzing three density metrics:
  - entropy
  - branch density (conditional jumps per KB)
  - API call density (indirect calls per KB)
"""
from __future__ import annotations

import struct
from typing import Optional

from .entropy import section_entropy


def separate_envelope_payload(
    data: bytes,
    sections: list[dict],
) -> dict:
    """Classify sections into envelope (packer) and payload (original code).

    Args:
        data: Full raw file bytes.
        sections: List of section dicts, each with at least:
            - name (str)
            - va (int) — virtual address / RVA
            - size (int) — virtual size
            - raw_size (int) — size of raw data (optional, defaults to size)
            - offset (int) — file offset to raw data (optional, computed from va)

    Returns:
        {
            "envelope_sections": [{"name", "entropy", "branch_density", "api_density"}, ...],
            "payload_sections":  [{"name", "entropy", "branch_density", "api_density"}, ...],
            "oep_candidates":    [{"section", "offset", "reason"}, ...],
        }
    """
    envelope: list[dict] = []
    payload: list[dict] = []
    oep_candidates: list[dict] = []

    for sec in sections:
        name = sec.get("name", "")
        size = sec.get("size", 0)
        raw_size = sec.get("raw_size", size)

        # Determine file offset for this section's raw data
        offset = sec.get("offset")
        if offset is None:
            # Fallback: try PointerToRawData, or use VA as rough offset
            offset = sec.get("PointerToRawData", sec.get("va", 0))

        # Extract section bytes
        if offset is not None and raw_size > 0 and offset + raw_size <= len(data):
            sec_data = data[offset : offset + raw_size]
        elif offset is not None and offset < len(data):
            sec_data = data[offset : min(offset + size, len(data))]
        else:
            sec_data = b""

        # Compute metrics
        ent = section_entropy(sec_data) if sec_data else 0.0
        branch_den = _branch_density(sec_data)
        api_den = _api_call_density(sec_data)

        info = {
            "name": name,
            "entropy": round(ent, 4),
            "branch_density": round(branch_den, 4),
            "api_density": round(api_den, 4),
        }

        # Classification heuristics
        # Envelope: high entropy, low branch density, low API density
        # Payload:  moderate entropy, higher branch/API density
        is_envelope = (ent > 6.5 and branch_den < 5.0 and api_den < 2.0)
        is_payload = (branch_den > 8.0 or api_den > 3.0) and ent < 7.0

        if is_envelope:
            envelope.append(info)
        elif is_payload:
            payload.append(info)
        else:
            # Ambiguous — classify by entropy
            if ent > 6.5:
                envelope.append(info)
            else:
                payload.append(info)

        # OEP candidate detection: look for a tail jump (E9/FF25) near
        # the end of high-entropy sections that jumps to lower-entropy code
        if is_envelope and sec_data:
            oep = _find_oep_candidate(sec_data, name, offset)
            if oep:
                oep_candidates.append(oep)

    return {
        "envelope_sections": envelope,
        "payload_sections": payload,
        "oep_candidates": oep_candidates,
    }


# ------------------------------------------------------------------
# Density metrics
# ------------------------------------------------------------------

def _branch_density(data: bytes) -> float:
    """Count conditional jump instructions per KB.

    Counts:
    - 0x74 / 0x75  (JZ/JNZ short)
    - 0x0F 0x80..0x8F (Jcc near)
    """
    if len(data) < 2:
        return 0.0

    count = 0
    i = 0
    while i < len(data):
        b = data[i]
        if b in (0x74, 0x75):
            count += 1
            i += 2  # skip rel8
        elif b == 0x0F and i + 1 < len(data) and 0x80 <= data[i + 1] <= 0x8F:
            count += 1
            i += 6  # skip 0F xx rel32
        else:
            i += 1

    return (count / len(data)) * 1024


def _api_call_density(data: bytes) -> float:
    """Count indirect call/jump instructions (FF 15 / FF 25) per KB.

    FF 15 disp32 = call [mem] (IAT call)
    FF 25 disp32 = jmp  [mem] (IAT thunk / PLT-like)
    """
    if len(data) < 6:
        return 0.0

    count = 0
    i = 0
    while i < len(data) - 5:
        if data[i] == 0xFF and data[i + 1] in (0x15, 0x25):
            count += 1
            i += 6
        else:
            i += 1

    return (count / len(data)) * 1024


# ------------------------------------------------------------------
# OEP candidate detection
# ------------------------------------------------------------------

def _find_oep_candidate(
    sec_data: bytes,
    section_name: str,
    file_offset: int,
) -> Optional[dict]:
    """Look for a tail jump (E9 rel32 or FF 25) in the last 256 bytes
    of a section — a common packer pattern where the stub jumps to the OEP.
    """
    tail = sec_data[-256:] if len(sec_data) > 256 else sec_data
    tail_base = len(sec_data) - len(tail)

    # Search backwards for E9 (JMP rel32)
    for i in range(len(tail) - 5, -1, -1):
        if tail[i] == 0xE9:
            rel32 = struct.unpack_from("<i", tail, i + 1)[0]
            target_offset = (tail_base + i + 5) + rel32
            return {
                "section": section_name,
                "offset": file_offset + tail_base + i,
                "target_offset": target_offset,
                "reason": f"tail JMP rel32 at end of {section_name}",
            }

    # Search for FF 25 (JMP [mem])
    for i in range(len(tail) - 6, -1, -1):
        if tail[i] == 0xFF and tail[i + 1] == 0x25:
            return {
                "section": section_name,
                "offset": file_offset + tail_base + i,
                "reason": f"indirect JMP [mem] at end of {section_name}",
            }

    return None
