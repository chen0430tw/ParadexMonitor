"""
Packer identification — detect UPX, VMProtect, Themida, and generic packing.
"""
from __future__ import annotations

from pathlib import Path
from typing import Optional

from .entropy import section_entropy


def detect_packer(path: str) -> dict:
    """Detect whether a PE/ELF binary is packed and identify the packer.

    Returns:
        {
            "packed": bool,
            "packer": str,        # "UPX", "VMProtect", "Themida", "unknown", ""
            "confidence": float,  # 0.0 .. 1.0
            "details": str,
        }
    """
    p = Path(path)
    if not p.exists():
        return {"packed": False, "packer": "", "confidence": 0.0,
                "details": f"file not found: {path}"}

    data = p.read_bytes()
    if len(data) < 64:
        return {"packed": False, "packer": "", "confidence": 0.0,
                "details": "file too small"}

    signals: list[tuple[str, float, str]] = []  # (packer, confidence, detail)

    # ---- UPX ----
    if b"UPX!" in data:
        signals.append(("UPX", 0.95, "UPX! magic found in file"))
    if _has_section_name(data, b".UPX0") or _has_section_name(data, b".UPX1"):
        signals.append(("UPX", 0.90, "UPX section names (.UPX0/.UPX1)"))

    # ---- VMProtect ----
    if _has_section_name(data, b".vmp0") or _has_section_name(data, b".vmp1"):
        signals.append(("VMProtect", 0.85, "VMProtect section names (.vmp0/.vmp1)"))

    # ---- Themida ----
    if _has_section_name(data, b".themida"):
        signals.append(("Themida", 0.85, "Themida section name"))
    if _has_section_name(data, b".winlice"):
        signals.append(("Themida", 0.80, "WinLicense section name"))

    # ---- Generic packing heuristics (PE only) ----
    is_pe = data[:2] == b"MZ"
    if is_pe:
        pe_signals = _pe_heuristics(path, data)
        signals.extend(pe_signals)

    # ---- Entropy heuristic (any format) ----
    overall_ent = section_entropy(data)
    if overall_ent > 7.2:
        signals.append(("unknown", 0.70,
                         f"very high overall entropy: {overall_ent:.2f}"))
    elif overall_ent > 7.0:
        signals.append(("unknown", 0.50,
                         f"high overall entropy: {overall_ent:.2f}"))

    # ---- Aggregate ----
    if not signals:
        return {"packed": False, "packer": "", "confidence": 0.0,
                "details": "no packing indicators found"}

    # Pick highest confidence signal
    signals.sort(key=lambda s: s[1], reverse=True)
    best_packer, best_conf, best_detail = signals[0]

    # Combine details
    all_details = "; ".join(f"[{p} {c:.0%}] {d}" for p, c, d in signals)

    return {
        "packed": True,
        "packer": best_packer,
        "confidence": round(best_conf, 2),
        "details": all_details,
    }


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

def _has_section_name(data: bytes, name: bytes) -> bool:
    """Check if a section name appears in the file (simple byte search)."""
    return name in data


def _pe_heuristics(path: str, data: bytes) -> list[tuple[str, float, str]]:
    """PE-specific packing heuristics using pefile."""
    signals: list[tuple[str, float, str]] = []

    try:
        import pefile
    except ImportError:
        return signals

    try:
        pe = pefile.PE(path, fast_load=True)
    except Exception:
        return signals

    try:
        # Check section entropy
        high_entropy_sections = 0
        for sec in pe.sections:
            ent = sec.get_entropy()
            name = sec.Name.rstrip(b"\x00").decode("ascii", errors="replace")
            if ent > 7.0 and sec.Misc_VirtualSize > 1024:
                high_entropy_sections += 1
                signals.append(("unknown", 0.60,
                                f"section '{name}' entropy={ent:.2f}"))

        # Minimal IAT check
        pe.parse_data_directories(directories=[1])  # IMPORT
        total_imports = 0
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                total_imports += len(entry.imports)

        if total_imports <= 3:
            signals.append(("unknown", 0.65,
                            f"minimal IAT: only {total_imports} import(s)"))
    finally:
        pe.close()

    return signals
