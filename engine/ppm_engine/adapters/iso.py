"""
ISO image adapter -- parse ISO 9660 / UDF disk images.

Major phishing delivery vector since 2022: ISO files bypass MOTW
(Mark of the Web) on older Windows, allowing direct execution of
embedded executables without SmartScreen warnings.
"""
from __future__ import annotations

from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class ISOInfo:
    volume_id: str = ""
    system_id: str = ""
    publisher: str = ""
    files: list = field(default_factory=list)
    strings: list = field(default_factory=list)
    num_files: int = 0
    has_udf: bool = False
    total_size: int = 0


def is_iso(path: str) -> bool:
    """Check for ISO 9660 magic at sector 16 (offset 0x8000)."""
    try:
        with open(path, "rb") as f:
            f.seek(0x8001)
            magic = f.read(5)
        return magic == b"CD001"
    except Exception:
        return False


def parse(path: str) -> Optional[ISOInfo]:
    """Parse an ISO image and extract file listing + metadata."""
    try:
        import pycdlib
    except ImportError:
        return None

    info = ISOInfo()
    info.total_size = Path(path).stat().st_size

    try:
        iso = pycdlib.PyCdlib()
        iso.open(path)

        # Volume descriptor
        pvd = iso.pvd
        info.volume_id = pvd.volume_identifier.decode('ascii', errors='replace').strip()
        info.system_id = pvd.system_identifier.decode('ascii', errors='replace').strip()
        try:
            pub = pvd.publisher_identifier
            info.publisher = (pub.identifier if hasattr(pub, 'identifier') else pub).decode('ascii', errors='replace').strip()
        except Exception:
            pass

        if info.volume_id:
            info.strings.append(f"Volume: {info.volume_id}")
        if info.publisher:
            info.strings.append(f"Publisher: {info.publisher}")

        # Check for UDF
        try:
            iso.has_udf
            info.has_udf = True
        except Exception:
            pass

        # Walk directory tree
        def _walk(dirpath):
            try:
                for child in iso.list_children(iso_path=dirpath):
                    name = child.file_identifier().decode('ascii', errors='replace')
                    if name in ('.', '..', '\x00'):
                        continue
                    full = dirpath.rstrip('/') + '/' + name
                    if child.is_dir():
                        info.files.append(full + '/')
                        info.strings.append(f"Dir: {full}")
                        _walk(full)
                    else:
                        size = child.data_length
                        info.files.append(full)
                        info.strings.append(f"File: {full} ({size} bytes)")

                        # Flag suspicious files
                        lower = name.lower().rstrip(';1')  # ISO 9660 adds ;1
                        if lower.endswith(('.exe', '.dll', '.scr', '.pif', '.bat',
                                          '.cmd', '.ps1', '.vbs', '.js', '.lnk',
                                          '.hta', '.msi', '.wsf')):
                            info.strings.append(f"Executable: {full}")
            except Exception:
                pass

        _walk('/')
        iso.close()

    except Exception:
        return None

    info.num_files = len([f for f in info.files if not f.endswith('/')])
    return info
