"""
Detect XOR-encoded payloads, dynamic API resolution, and RWX shellcode injection.

Uses callgraph topology to:
1. Find XOR decode loops (xor in a loop body)
2. Trace data references from XOR-using functions
3. Only scan data regions referenced by suspicious code paths

Covers three common malware techniques:
1. XOR-encrypted data blobs decoded at runtime
2. LoadLibraryA + GetProcAddress dynamic import resolution
3. VirtualAlloc(PAGE_EXECUTE_READWRITE) shellcode execution
"""
from __future__ import annotations

from .base import Pattern, PatternMatch


class XorPayloadPattern(Pattern):
    """Detect XOR-encoded payloads and shellcode injection patterns."""

    @property
    def name(self) -> str:
        return "xor_payload"

    def scan(self, adapter, callgraph=None, depgraph=None) -> list[PatternMatch]:
        matches: list[PatternMatch] = []

        imports = {}
        try:
            for imp in adapter.imports():
                fn = imp.get("name") or imp.get("import_name", "")
                if fn:
                    imports[fn] = imp.get("rva", 0)
        except Exception:
            pass

        # --- Check 1: Dynamic API resolution (LoadLibrary + GetProcAddress) ---
        has_loadlib = any(k for k in imports if "LoadLibrary" in k)
        has_getproc = "GetProcAddress" in imports

        if has_loadlib and has_getproc:
            matches.append(PatternMatch(
                pattern_name="xor_payload",
                confidence=0.5,
                location=imports.get("GetProcAddress", 0),
                details={"technique": "dynamic_api_resolution",
                         "apis": ["LoadLibraryA/W", "GetProcAddress"]},
                description="Dynamic API resolution via LoadLibrary + GetProcAddress"
            ))

        # --- Check 2: RWX memory allocation (shellcode injection) ---
        has_valloc = "VirtualAlloc" in imports or "VirtualAllocEx" in imports
        has_vprotect = "VirtualProtect" in imports or "VirtualProtectEx" in imports

        if has_valloc or has_vprotect:
            rwx_conf = 0.3
            if has_loadlib and has_getproc:
                rwx_conf = 0.6
            if has_valloc and has_vprotect:
                rwx_conf = 0.7

            matches.append(PatternMatch(
                pattern_name="xor_payload",
                confidence=rwx_conf,
                location=imports.get("VirtualAlloc", imports.get("VirtualAllocEx", 0)),
                details={"technique": "rwx_allocation",
                         "apis": [k for k in imports if "Virtual" in k]},
                description="Executable memory allocation (VirtualAlloc/VirtualProtect)"
            ))

        # --- Check 3: XOR decode loops via callgraph topology ---
        xor_funcs = self._find_xor_functions(adapter, callgraph)
        if xor_funcs:
            # Found functions with XOR decode patterns — scan their data refs
            xor_blobs = self._scan_xor_from_topology(adapter, xor_funcs)
            matches.extend(xor_blobs)

            # If no specific blobs found but XOR loops exist, still report
            if not xor_blobs:
                for func_rva, info in xor_funcs.items():
                    matches.append(PatternMatch(
                        pattern_name="xor_payload",
                        confidence=0.5,
                        location=func_rva,
                        details={"technique": "xor_loop", **info},
                        description=f"XOR decode loop at sub_{func_rva:X}: {info.get('pattern', '')}"
                    ))

        # --- Boost confidence if multiple indicators combine ---
        techniques = set(m.details.get("technique", "") for m in matches)
        if len(techniques) >= 2:
            for m in matches:
                m.confidence = min(m.confidence + 0.15, 0.95)

        return matches

    def _find_xor_functions(self, adapter, callgraph) -> dict[int, dict]:
        """Find functions containing XOR decode loops using disassembly.

        Looks for the pattern: a loop body containing XOR with a register
        operand (not xor reg,reg which is just zeroing).
        """
        import capstone

        try:
            pe = adapter._pe
        except AttributeError:
            return {}

        text_sec = None
        for sec in pe.sections:
            if b".text" in sec.Name:
                text_sec = sec
                break
        if not text_sec:
            return {}

        text_data = text_sec.get_data()
        text_rva = text_sec.VirtualAddress

        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        md.detail = True

        # Get function boundaries from callgraph
        func_bounds = []
        if callgraph:
            for rva, fn in sorted(callgraph.functions.items()):
                if fn.is_import:
                    continue
                size = fn.size if fn.size else 0x200
                func_bounds.append((rva, size))

        if not func_bounds:
            # Fallback: scan entire .text
            func_bounds = [(text_rva, len(text_data))]

        xor_funcs = {}

        for func_rva, func_size in func_bounds:
            offset = func_rva - text_rva
            if offset < 0 or offset >= len(text_data):
                continue
            end = min(offset + func_size, len(text_data))
            chunk = text_data[offset:end]

            has_xor = False
            has_loop = False
            xor_key_imm = None

            for insn in md.disasm(chunk, func_rva):
                mn = insn.mnemonic

                # Detect XOR with non-self operand (actual encryption, not zeroing)
                if mn == "xor":
                    ops = insn.op_str.split(",")
                    if len(ops) == 2:
                        a, b = ops[0].strip(), ops[1].strip()
                        # Skip xor reg, reg (zeroing pattern)
                        if a.lower() != b.lower():
                            has_xor = True
                            # Try to capture XOR key if immediate
                            b_strip = b.strip()
                            try:
                                xor_key_imm = int(b_strip, 0)
                            except ValueError:
                                pass

                # Detect backward jumps (loop indicator)
                if mn in ("jne", "jnz", "jl", "jle", "jb", "jbe",
                          "loop", "jmp", "jge", "jg", "ja", "jae"):
                    try:
                        target = int(insn.op_str.strip(), 0)
                        if target < insn.address:  # backward jump = loop
                            has_loop = True
                    except ValueError:
                        pass

            if has_xor and has_loop:
                info = {"pattern": "xor_in_loop"}
                if xor_key_imm is not None:
                    info["xor_key"] = f"0x{xor_key_imm:02X}"
                xor_funcs[func_rva] = info

        return xor_funcs

    def _scan_xor_from_topology(self, adapter, xor_funcs: dict) -> list[PatternMatch]:
        """Given functions with XOR loops, find their data references and decode."""
        from ppm_engine.unpack.xor_crack import single_byte_xor

        results = []

        try:
            pe = adapter._pe
        except AttributeError:
            return results

        # Collect data sections
        data_map = {}  # rva -> (name, raw_bytes)
        for sec in pe.sections:
            name = sec.Name.rstrip(b"\x00").decode("ascii", errors="replace")
            if any(n in name.lower() for n in (".data", ".rdata")):
                data_map[sec.VirtualAddress] = (name, sec.get_data())

        if not data_map:
            return results

        # For each XOR function, try to decode with its key
        for func_rva, info in xor_funcs.items():
            key_str = info.get("xor_key")
            if not key_str:
                continue

            try:
                key = int(key_str, 0) & 0xFF
            except ValueError:
                continue

            if key == 0:
                continue

            # Scan data sections for strings decodable with this key
            for sec_rva, (sec_name, raw) in data_map.items():
                decoded_strings = self._decode_with_key(raw, key, sec_rva, sec_name)
                for ds in decoded_strings:
                    results.append(ds)

                if len(results) > 10:
                    return results

        return results

    def _decode_with_key(self, data: bytes, key: int,
                         base_rva: int, sec_name: str) -> list[PatternMatch]:
        """Decode data with a specific XOR key, return meaningful strings."""
        results = []

        run_start = -1
        run_len = 0

        for i in range(len(data)):
            ch = data[i] ^ key
            if 0x20 <= ch <= 0x7E:
                if run_start < 0:
                    run_start = i
                run_len += 1
            elif ch == 0x00 and run_len >= 6:
                decoded = bytes(b ^ key for b in data[run_start:run_start + run_len])
                decoded_str = decoded.decode("ascii", errors="replace")
                original = data[run_start:run_start + run_len]

                # Must not already be readable ASCII
                if all(0x20 <= b <= 0x7E for b in original):
                    run_start = -1
                    run_len = 0
                    continue

                # Must look like a real string
                if self._looks_like_real_string(decoded_str):
                    results.append(PatternMatch(
                        pattern_name="xor_payload",
                        confidence=min(0.5 + len(decoded_str) * 0.05, 0.90),
                        location=base_rva + run_start,
                        details={
                            "technique": "xor_encoded_string",
                            "key": f"0x{key:02X}",
                            "section": sec_name,
                            "decoded": decoded_str[:80],
                            "length": len(decoded_str),
                        },
                        description=f"XOR-encoded string (key=0x{key:02X}): \"{decoded_str[:60]}\""
                    ))

                run_start = -1
                run_len = 0
            else:
                run_start = -1
                run_len = 0

        return results

    @staticmethod
    def _looks_like_real_string(s: str) -> bool:
        """Check if a decoded string looks like a real API name, DLL, path, or word."""
        _SUSPICIOUS = [
            ".dll", ".exe", ".sys", ".bat", ".ps1", ".vbs", ".tmp",
            "http", "ftp:", "\\\\", "://",
            "cmd", "shell", "exec", "inject", "hook",
            "password", "token", "secret", "payload", "active",
            "kernel32", "ntdll", "user32", "advapi", "ws2_32", "wininet",
            "LoadLibrary", "GetProcAddress", "VirtualAlloc",
            "CreateProcess", "WriteProcessMemory", "NtCreate",
            "RegOpenKey", "RegSetValue",
            "MessageBox", "WinExec", "ShellExecute",
        ]
        sl = s.lower()
        for sus in _SUSPICIOUS:
            if sus.lower() in sl:
                return True

        # CamelCase (typical Windows API names): >= 2 lower→upper transitions
        transitions = sum(1 for i in range(1, len(s))
                          if s[i-1].islower() and s[i].isupper())
        if transitions >= 2 and len(s) >= 8:
            return True

        # File path
        if ('\\' in s and len(s) >= 8) or ('/' in s and len(s) >= 8):
            return True

        return False
