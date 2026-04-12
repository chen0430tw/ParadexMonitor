"""
MSI (Windows Installer) adapter -- parse .msi installer packages.

Extracts CustomAction table (arbitrary code execution), File table,
Registry table, and Property table for security analysis.

MSI files are OLE2 Compound Binary Files containing a relational database.
"""
from __future__ import annotations

from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class MSIInfo:
    product_name: str = ""
    manufacturer: str = ""
    product_version: str = ""
    custom_actions: list = field(default_factory=list)
    files: list = field(default_factory=list)
    registry_entries: list = field(default_factory=list)
    properties: dict = field(default_factory=dict)
    tables: list = field(default_factory=list)
    strings: list = field(default_factory=list)
    num_files: int = 0


def is_msi(path: str) -> bool:
    """Check if file is an MSI (OLE2 magic: D0 CF 11 E0)."""
    try:
        with open(path, "rb") as f:
            return f.read(4) == b"\xD0\xCF\x11\xE0"
    except Exception:
        return False


def _safe_rows(table):
    """Safely get rows from a pymsi table."""
    try:
        return table.rows if table.rows else []
    except Exception:
        return []


def _safe_str(val) -> str:
    """Convert any value to string safely."""
    if val is None:
        return ""
    return str(val)


def parse(path: str) -> Optional[MSIInfo]:
    """Parse an MSI file and extract security-relevant tables."""
    info = MSIInfo()

    try:
        from pymsi import Package
        pkg = Package(path)
        tables = pkg.tables

        info.tables = list(tables.keys())

        # Property table
        if "Property" in tables:
            for row in _safe_rows(tables["Property"]):
                try:
                    key = _safe_str(row[0])
                    val = _safe_str(row[1])
                    info.properties[key] = val
                    info.strings.append(f"{key}={val}")
                    if key == "ProductName": info.product_name = val
                    elif key == "Manufacturer": info.manufacturer = val
                    elif key == "ProductVersion": info.product_version = val
                except Exception:
                    pass

        # CustomAction table
        if "CustomAction" in tables:
            for row in _safe_rows(tables["CustomAction"]):
                try:
                    ca = {
                        "action": _safe_str(row[0]),
                        "type": int(row[1]) if row[1] else 0,
                        "source": _safe_str(row[2]),
                        "target": _safe_str(row[3]),
                    }
                    info.custom_actions.append(ca)
                    info.strings.append(f"CustomAction: {ca['action']} type={ca['type']} src={ca['source']}")
                except Exception:
                    pass

        # File table
        if "File" in tables:
            for row in _safe_rows(tables["File"]):
                try:
                    fname = _safe_str(row[2]) if len(row) > 2 else _safe_str(row[0])
                    info.files.append(fname)
                    info.strings.append(f"File: {fname}")
                except Exception:
                    pass

        # Registry table
        if "Registry" in tables:
            for row in _safe_rows(tables["Registry"]):
                try:
                    roots = {-1: "HKCR", 0: "HKCR", 1: "HKCU", 2: "HKLM", 3: "HKU"}
                    root = int(row[1]) if row[1] else -1
                    key = _safe_str(row[2])
                    name = _safe_str(row[3])
                    value = _safe_str(row[4]) if len(row) > 4 else ""
                    info.registry_entries.append({"root": roots.get(root, "?"), "key": key, "name": name})
                    info.strings.append(f"Registry: {roots.get(root,'')}\\{key}\\{name}")
                except Exception:
                    pass

        # ServiceInstall table
        if "ServiceInstall" in tables:
            for row in _safe_rows(tables["ServiceInstall"]):
                try:
                    svc_name = _safe_str(row[1])
                    info.strings.append(f"ServiceInstall: {svc_name}")
                except Exception:
                    pass

        # If no strings from tables, at least report table names
        if not info.strings:
            for tname in info.tables:
                if not tname.startswith("_"):
                    info.strings.append(f"Table: {tname}")

        pkg.close()

    except ImportError:
        # Fallback: olefile
        try:
            import olefile
            ole = olefile.OleFileIO(path)
            info.tables = ["/".join(s) for s in ole.listdir()]
            for s in info.tables:
                info.strings.append(s)
            ole.close()
        except Exception:
            return None
    except Exception:
        return None

    info.num_files = len(info.files)
    return info
