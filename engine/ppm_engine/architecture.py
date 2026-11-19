"""Architecture selection for PE instruction analysis."""
from __future__ import annotations


def pe_bitness(pe) -> int:
    machine = pe.FILE_HEADER.Machine
    magic = pe.OPTIONAL_HEADER.Magic
    if machine == 0x14C and magic == 0x10B:
        return 32
    if machine == 0x8664 and magic == 0x20B:
        return 64
    raise ValueError(f"Unsupported PE architecture: machine=0x{machine:X}, magic=0x{magic:X}")


def capstone_mode(pe) -> int:
    from capstone import CS_MODE_32, CS_MODE_64
    return CS_MODE_32 if pe_bitness(pe) == 32 else CS_MODE_64
