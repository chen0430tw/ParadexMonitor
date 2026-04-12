"""
MSIX / AppX adapter -- parse Windows modern application packages.

MSIX/AppX are signed ZIP archives containing AppxManifest.xml.
Extracts package identity, capabilities/permissions, and entry points.
"""
from __future__ import annotations

import zipfile
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional
import xml.etree.ElementTree as ET


@dataclass
class MSIXInfo:
    package_name: str = ""
    publisher: str = ""
    version: str = ""
    entry_point: str = ""
    capabilities: list = field(default_factory=list)
    files: list = field(default_factory=list)
    strings: list = field(default_factory=list)
    num_files: int = 0
    is_signed: bool = False


def is_msix(path: str) -> bool:
    """Check if ZIP contains AppxManifest.xml."""
    try:
        with zipfile.ZipFile(path, 'r') as z:
            return "AppxManifest.xml" in z.namelist()
    except Exception:
        return False


def parse(path: str) -> Optional[MSIXInfo]:
    """Parse an MSIX/AppX package."""
    try:
        z = zipfile.ZipFile(path, 'r')
    except Exception:
        return None

    info = MSIXInfo()

    # File listing
    for name in z.namelist():
        info.files.append(name)
        lower = name.lower()
        if lower.endswith(('.exe', '.dll')):
            info.strings.append(f"Executable: {name}")
        elif lower.endswith(('.ps1', '.bat', '.cmd', '.vbs', '.js')):
            info.strings.append(f"Script: {name}")

    info.num_files = len(info.files)

    # Check for signature
    info.is_signed = "AppxSignature.p7x" in z.namelist()

    # Parse AppxManifest.xml
    try:
        manifest = z.read("AppxManifest.xml").decode("utf-8", errors="replace")
        root = ET.fromstring(manifest)

        # Namespace handling (MSIX uses a default namespace)
        ns = ""
        if root.tag.startswith("{"):
            ns = root.tag.split("}")[0] + "}"

        # Identity
        identity = root.find(f".//{ns}Identity")
        if identity is not None:
            info.package_name = identity.get("Name", "")
            info.publisher = identity.get("Publisher", "")
            info.version = identity.get("Version", "")
            info.strings.append(f"Package: {info.package_name}")
            info.strings.append(f"Publisher: {info.publisher}")
            info.strings.append(f"Version: {info.version}")

        # Entry point
        app = root.find(f".//{ns}Application")
        if app is not None:
            info.entry_point = app.get("Executable", "")
            if info.entry_point:
                info.strings.append(f"EntryPoint: {info.entry_point}")

        # Capabilities
        for cap in root.findall(f".//{ns}Capability"):
            name = cap.get("Name", "")
            if name:
                info.capabilities.append(name)
                info.strings.append(f"Capability: {name}")

        # Restricted capabilities
        for cap in root.iter():
            if "Capability" in cap.tag:
                name = cap.get("Name", "")
                if name and name not in info.capabilities:
                    info.capabilities.append(name)
                    info.strings.append(f"Capability: {name}")

    except Exception:
        pass

    z.close()
    return info
