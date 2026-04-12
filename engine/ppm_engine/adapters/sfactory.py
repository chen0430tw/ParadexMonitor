"""
Setup Factory adapter -- parse Setup Factory installer packages.

Uses sfextract (CybercentreCanada) for extraction.
Analyzes embedded files and scripts for security patterns.
"""
from __future__ import annotations

from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional
import tempfile
import os


@dataclass
class SFInfo:
    version: str = ""
    files: list = field(default_factory=list)
    strings: list = field(default_factory=list)
    num_files: int = 0


def is_setup_factory(path: str) -> bool:
    """Check if file is a Setup Factory installer."""
    try:
        from sfextract.main import extract
        with tempfile.TemporaryDirectory() as tmp:
            ext = extract(path, tmp)
            return ext is not None and hasattr(ext, 'version')
    except Exception:
        return False


def parse(path: str) -> Optional[SFInfo]:
    """Parse a Setup Factory installer and extract file list + metadata."""
    try:
        from sfextract.main import extract
    except ImportError:
        return None

    info = SFInfo()

    try:
        with tempfile.TemporaryDirectory() as tmp:
            ext = extract(path, tmp)
            if ext is None:
                return None

            info.version = str(getattr(ext, 'version', 'unknown'))

            # Enumerate extracted files
            if hasattr(ext, 'files'):
                for f in ext.files:
                    fname = str(getattr(f, 'name', f))
                    info.files.append(fname)
                    info.strings.append(f"File: {fname}")

            # Also walk the temp directory for any extracted content
            for root, dirs, files in os.walk(tmp):
                for f in files:
                    fpath = os.path.join(root, f)
                    relpath = os.path.relpath(fpath, tmp)
                    if relpath not in info.files:
                        info.files.append(relpath)
                        info.strings.append(f"File: {relpath}")

                    # Extract strings from script-like files
                    if f.endswith(('.lua', '.txt', '.ini', '.bat', '.cmd', '.ps1', '.vbs', '.js')):
                        try:
                            content = open(fpath, 'r', errors='replace').read()
                            for line in content.splitlines():
                                line = line.strip()
                                if line and len(line) > 3:
                                    info.strings.append(line)
                        except Exception:
                            pass

    except Exception:
        return None

    info.num_files = len(info.files)
    return info
