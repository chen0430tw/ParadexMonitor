"""
Auto-detect binary format from file header magic bytes.
"""
from pathlib import Path
from dataclasses import dataclass, field


@dataclass
class FileInfo:
    path: str
    format: str              # "PE32", "PE64", "PE64_DRIVER", "ELF64", "MACHO", "SHELLCODE", ...
    arch: str = ""           # "x86", "x64", "arm64", ...
    packed: bool = False
    packer: str = ""         # "UPX", "VMProtect", "", ...
    entry_point: int = 0
    sections: list = field(default_factory=list)
    imports: dict = field(default_factory=dict)


def detect(path: str) -> FileInfo:
    """Detect file format and return basic info."""
    p = Path(path)
    if not p.exists():
        return FileInfo(path=path, format="NOT_FOUND")

    with open(p, "rb") as f:
        magic = f.read(16)

    if len(magic) < 4:
        return FileInfo(path=path, format="TOO_SMALL")

    # PE (MZ header)
    if magic[:2] == b"MZ":
        return _detect_pe(path)

    # ELF
    if magic[:4] == b"\x7fELF":
        cls = magic[4]  # 1=32bit, 2=64bit
        fmt = "ELF64" if cls == 2 else "ELF32"
        return FileInfo(path=path, format=fmt, arch="x64" if cls == 2 else "x86")

    # Mach-O
    if magic[:4] in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf",
                      b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"):
        return FileInfo(path=path, format="MACHO")

    # Mach-O fat binary
    if magic[:4] in (b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca"):
        return FileInfo(path=path, format="MACHO_FAT")

    # Fallback: raw shellcode
    return FileInfo(path=path, format="SHELLCODE")


def _detect_pe(path: str) -> FileInfo:
    """Detailed PE detection using pefile."""
    try:
        import pefile
        pe = pefile.PE(path, fast_load=True)
    except Exception:
        return FileInfo(path=path, format="PE_CORRUPT")

    is64 = pe.OPTIONAL_HEADER.Magic == 0x20B
    arch = "x64" if is64 else "x86"

    # Determine sub-type
    # Subsystem: 1=NATIVE (driver), 2=WINDOWS_GUI, 3=WINDOWS_CUI
    subsys = pe.OPTIONAL_HEADER.Subsystem
    is_dll = pe.FILE_HEADER.Characteristics & 0x2000  # IMAGE_FILE_DLL

    if subsys == 1:  # NATIVE = kernel driver
        fmt = "PE64_DRIVER" if is64 else "PE32_DRIVER"
    elif is_dll:
        fmt = "PE64_DLL" if is64 else "PE32_DLL"
    else:
        fmt = "PE64" if is64 else "PE32"

    info = FileInfo(
        path=path,
        format=fmt,
        arch=arch,
        entry_point=pe.OPTIONAL_HEADER.AddressOfEntryPoint,
    )

    # Quick packing heuristic: check section entropy
    for sec in pe.sections:
        name = sec.Name.rstrip(b"\x00").decode("ascii", errors="replace")
        entropy = sec.get_entropy()
        info.sections.append({"name": name, "entropy": round(entropy, 2),
                              "va": sec.VirtualAddress, "size": sec.Misc_VirtualSize})
        if entropy > 7.0 and sec.Misc_VirtualSize > 1024:
            info.packed = True

    # Minimal IAT check: very few imports = likely packed
    pe.parse_data_directories(directories=[1])  # IMAGE_DIRECTORY_ENTRY_IMPORT
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode("ascii", errors="replace")
            funcs = []
            for imp in entry.imports:
                if imp.name:
                    funcs.append(imp.name.decode("ascii", errors="replace"))
            info.imports[dll_name] = funcs

        total_imports = sum(len(v) for v in info.imports.values())
        if total_imports <= 3 and len(info.sections) <= 2:
            info.packed = True
            info.packer = "unknown (minimal IAT)"

    pe.close()
    return info
