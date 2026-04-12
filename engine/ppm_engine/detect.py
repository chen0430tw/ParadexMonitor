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

    # LNK (Windows shortcut): magic 4C 00 00 00 + CLSID
    if magic[:4] == b"\x4c\x00\x00\x00" and len(magic) >= 16:
        # Verify CLSID: 00021401-0000-0000-C000-000000000046
        if magic[4:8] == b"\x01\x14\x02\x00":
            return FileInfo(path=path, format="LNK", arch="n/a")

    # MSI (OLE2 Compound Binary File)
    if magic[:4] == b"\xD0\xCF\x11\xE0":
        try:
            from ppm_engine.adapters.msi import is_msi
            if is_msi(path):
                return FileInfo(path=path, format="MSI", arch="n/a", packer="MSI")
        except Exception:
            pass
        return FileInfo(path=path, format="OLE2", arch="n/a")

    # ISO 9660 — check magic at sector 16
    if len(magic) >= 8:
        try:
            from ppm_engine.adapters.iso import is_iso
            if is_iso(path):
                return FileInfo(path=path, format="ISO", arch="n/a")
        except Exception:
            pass

    # MSIX / AppX (ZIP with AppxManifest.xml)
    if magic[:2] == b"PK":
        try:
            from ppm_engine.adapters.msix import is_msix
            if is_msix(path):
                return FileInfo(path=path, format="MSIX", arch="n/a")
        except Exception:
            pass

    # PE (MZ header) — check for NSIS, Inno Setup, PyInstaller, 7z SFX inside PE
    if magic[:2] == b"MZ":
        info = _detect_pe(path)
        try:
            with open(p, "rb") as f:
                pe_data = f.read(2 * 1024 * 1024)  # first 2MB

            # NSIS
            from ppm_engine.adapters.nsis import is_nsis
            if is_nsis(pe_data):
                info.format = "NSIS_" + ("UNINST" if info.format.startswith("PE32") else "INST")
                info.packer = "NSIS"
                return info

            # Inno Setup
            try:
                from ppm_engine.adapters.inno import is_inno_setup
                if is_inno_setup(pe_data):
                    info.format = "INNO_SETUP"
                    info.packer = "Inno Setup"
                    return info
            except Exception:
                pass

            # PyInstaller
            try:
                from ppm_engine.adapters.pyinst import is_pyinstaller
                if is_pyinstaller(pe_data):
                    info.format = "PYINSTALLER"
                    info.packer = "PyInstaller"
                    return info
            except Exception:
                pass

            # 7z SFX
            try:
                from ppm_engine.adapters.sfx7z import is_sfx7z
                if is_sfx7z(pe_data):
                    info.format = "SFX_7Z"
                    info.packer = "7z SFX"
                    return info
            except Exception:
                pass

        except Exception:
            pass
        return info

    # ELF
    if magic[:4] == b"\x7fELF":
        cls = magic[4]  # 1=32bit, 2=64bit
        fmt = "ELF64" if cls == 2 else "ELF32"
        return FileInfo(path=path, format=fmt, arch="x64" if cls == 2 else "x86")

    # Mach-O 32-bit
    if magic[:4] in (b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe"):
        return FileInfo(path=path, format="MACHO", arch="x86")
    # Mach-O 64-bit -- check CPU type for x64 vs arm64
    if magic[:4] in (b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe"):
        import struct
        # CPU type is at offset 4 (little-endian if LE magic, big-endian if BE)
        is_le = magic[:4] == b"\xcf\xfa\xed\xfe"
        cpu = struct.unpack("<I" if is_le else ">I", magic[4:8])[0] if len(magic) >= 8 else 0
        arch = "arm64" if cpu == 0x0100000C else "x64"
        return FileInfo(path=path, format="MACHO", arch=arch)

    # Mach-O fat binary (universal)
    if magic[:4] in (b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca"):
        return FileInfo(path=path, format="MACHO_FAT", arch="universal")

    # Common media / document formats (not analyzable binaries)
    _MEDIA_MAGIC = {
        # Images
        b"\xff\xd8\xff": "JPEG",
        b"\x89PNG": "PNG",
        b"GIF8": "GIF",
        b"BM": "BMP",
        b"RIFF": "RIFF",          # WAV, AVI, WebP
        b"II\x2a\x00": "TIFF",    # little-endian TIFF
        b"MM\x00\x2a": "TIFF",    # big-endian TIFF
        # Audio/Video
        b"\x1aE\xdf\xa3": "MKV",  # Matroska/WebM
        b"fLaC": "FLAC",
        b"OggS": "OGG",
        b"\xff\xfb": "MP3",
        b"\xff\xf3": "MP3",
        b"\xff\xf2": "MP3",
        b"ID3": "MP3",
        # Documents
        b"%PDF": "PDF",
        b"PK\x03\x04": "ZIP",     # ZIP/DOCX/XLSX/JAR/APK
    }
    for sig, fmt in _MEDIA_MAGIC.items():
        if magic[:len(sig)] == sig:
            return FileInfo(path=path, format=fmt, arch="n/a")

    # Mach-O / ftyp (MP4/MOV): "ftyp" at offset 4
    if len(magic) >= 8 and magic[4:8] == b"ftyp":
        return FileInfo(path=path, format="MP4", arch="n/a")

    # Check if the file is mostly printable text (not a binary)
    try:
        with open(p, "rb") as f:
            sample = f.read(4096)
        if sample:
            printable = sum(1 for b in sample if 0x20 <= b <= 0x7E or b in (0x09, 0x0A, 0x0D))
            ratio = printable / len(sample)
            if ratio > 0.85:
                return FileInfo(path=path, format="TEXT")
    except Exception:
        pass

    # Fallback: raw shellcode (unknown binary format)
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
