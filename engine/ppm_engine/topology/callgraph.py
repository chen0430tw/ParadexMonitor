"""
Build a call graph from a disassembled PE binary.

Uses capstone for x86-64 disassembly to identify function boundaries,
call targets, and build a complete caller/callee graph.
"""
from __future__ import annotations

import struct
from collections import deque
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ppm_engine.adapters.pe import PEAdapter

try:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_GRP_CALL, CS_GRP_JUMP
    _HAS_CAPSTONE = True
except ImportError:
    _HAS_CAPSTONE = False


# Common x64 function prologues (first bytes)
_PROLOGUES = [
    bytes([0x48, 0x89, 0x5C]),       # mov [rsp+...], rbx
    bytes([0x48, 0x83, 0xEC]),       # sub rsp, imm8
    bytes([0x48, 0x81, 0xEC]),       # sub rsp, imm32
    bytes([0x48, 0x8B, 0xC4]),       # mov rax, rsp
    bytes([0x40, 0x53]),             # push rbx
    bytes([0x40, 0x55]),             # push rbp
    bytes([0x40, 0x56]),             # push rsi
    bytes([0x40, 0x57]),             # push rdi
    bytes([0x55]),                   # push rbp
    bytes([0x53]),                   # push rbx
    bytes([0x56]),                   # push rsi
    bytes([0x57]),                   # push rdi
    bytes([0x41, 0x54]),             # push r12
    bytes([0x41, 0x55]),             # push r13
    bytes([0x41, 0x56]),             # push r14
    bytes([0x41, 0x57]),             # push r15
    bytes([0x4C, 0x8B, 0xDC]),      # mov r11, rsp
    bytes([0xCC]),                   # int3 padding (not a prologue, but boundary marker)
]


@dataclass
class Function:
    """Represents a single function in the call graph."""
    address: int
    name: str = ""
    size: int = 0
    calls: list[int] = field(default_factory=list)
    called_by: list[int] = field(default_factory=list)
    is_import: bool = False
    import_dll: str = ""
    import_name: str = ""

    def to_dict(self) -> dict:
        d = {
            "address": self.address,
            "name": self.name,
            "size": self.size,
            "calls": self.calls[:],
            "called_by": self.called_by[:],
        }
        if self.is_import:
            d["is_import"] = True
            d["import_dll"] = self.import_dll
            d["import_name"] = self.import_name
        return d


class CallGraph:
    """
    A directed graph of function call relationships extracted
    from a PE binary via disassembly.
    """

    def __init__(self) -> None:
        self.functions: dict[int, Function] = {}

    # ------------------------------------------------------------------
    # Construction
    # ------------------------------------------------------------------
    @classmethod
    def from_pe(cls, pe_adapter: PEAdapter) -> CallGraph:
        """Build call graph from a PEAdapter instance.

        Steps:
        1. Create Function nodes for each IAT import entry.
        2. Disassemble .text section using capstone.
        3. Find function boundaries (common prologues + call targets).
        4. Within each function, find call/jmp targets.
        5. Link caller -> callee bidirectionally.
        """
        graph = cls()

        # --- Step 1: Import nodes ---
        iat_map = pe_adapter._build_iat_map()  # rva -> (dll, func)
        image_base = pe_adapter._pe.OPTIONAL_HEADER.ImageBase
        for rva, (dll, func_name) in iat_map.items():
            fn = Function(
                address=rva,
                name=func_name,
                is_import=True,
                import_dll=dll,
                import_name=func_name,
            )
            graph.functions[rva] = fn

        # --- Step 2: Locate .text section ---
        text_sec = pe_adapter._find_section(".text")
        if text_sec is None:
            # Try other executable section names
            for sec in pe_adapter._pe.sections:
                chars = sec.Characteristics
                if chars & 0x20000000:  # IMAGE_SCN_MEM_EXECUTE
                    text_sec = sec
                    break
        if text_sec is None:
            return graph

        sec_rva = text_sec.VirtualAddress
        raw_offset = text_sec.PointerToRawData
        raw_size = text_sec.SizeOfRawData
        code = pe_adapter._raw[raw_offset: raw_offset + raw_size]

        if not code:
            return graph

        # --- Step 3: Find function boundaries ---
        # Start with known entry point
        entry_rva = pe_adapter.entry_point()
        func_starts: set[int] = set()
        if sec_rva <= entry_rva < sec_rva + len(code):
            func_starts.add(entry_rva)

        # Add export addresses as function starts
        pe_adapter._pe.parse_data_directories(directories=[0])  # EXPORT
        if hasattr(pe_adapter._pe, "DIRECTORY_ENTRY_EXPORT"):
            for exp in pe_adapter._pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if exp.address and sec_rva <= exp.address < sec_rva + len(code):
                    func_starts.add(exp.address)
                    name = exp.name.decode("ascii", errors="replace") if exp.name else f"ord#{exp.ordinal}"
                    if exp.address not in graph.functions:
                        graph.functions[exp.address] = Function(address=exp.address, name=name)

        # Scan for common prologues
        for i in range(len(code)):
            rva_i = sec_rva + i
            for prologue in _PROLOGUES:
                plen = len(prologue)
                if prologue[0] == 0xCC:
                    continue  # skip int3, handled differently
                if i + plen <= len(code) and code[i: i + plen] == prologue:
                    # Verify alignment or preceded by ret/int3/nop
                    if i == 0 or code[i - 1] in (0xC3, 0xCC, 0xCB, 0x90):
                        func_starts.add(rva_i)
                    elif i >= 2 and code[i - 2: i] == b"\xC2\x00":  # ret imm16
                        func_starts.add(rva_i)
                    break

        # --- Step 4: Disassemble and find calls ---
        if not _HAS_CAPSTONE:
            # Fallback: raw byte scan for E8 rel32 and FF 15 disp32
            graph._scan_calls_raw(code, sec_rva, func_starts, iat_map)
            return graph

        md = Cs(CS_ARCH_X86, CS_MODE_64)
        md.detail = True

        # First pass: collect all direct call targets as additional function starts
        call_targets: set[int] = set()
        for insn in md.disasm(code, sec_rva):
            if insn.group(CS_GRP_CALL):
                # Direct call: E8 rel32
                if insn.bytes[0] == 0xE8 and len(insn.bytes) == 5:
                    rel32 = struct.unpack_from("<i", bytes(insn.bytes), 1)[0]
                    target = insn.address + 5 + rel32
                    if sec_rva <= target < sec_rva + len(code):
                        call_targets.add(target)

        func_starts |= call_targets

        # Sort function starts, assign sizes
        sorted_starts = sorted(func_starts)
        for idx, start_rva in enumerate(sorted_starts):
            if start_rva in graph.functions:
                # Already exists (import or export), update if not import
                if graph.functions[start_rva].is_import:
                    continue
            end_rva = sorted_starts[idx + 1] if idx + 1 < len(sorted_starts) else sec_rva + len(code)
            size = end_rva - start_rva
            if start_rva not in graph.functions:
                name = f"sub_{start_rva:X}"
                graph.functions[start_rva] = Function(address=start_rva, name=name, size=size)
            else:
                graph.functions[start_rva].size = size

        # Second pass: within each function, find call targets
        for fn_addr in sorted(f for f in graph.functions if not graph.functions[f].is_import):
            fn = graph.functions[fn_addr]
            if fn.size <= 0:
                continue
            offset = fn_addr - sec_rva
            if offset < 0 or offset >= len(code):
                continue
            end = min(offset + fn.size, len(code))
            fn_code = code[offset:end]

            for insn in md.disasm(fn_code, fn_addr):
                if not insn.group(CS_GRP_CALL):
                    continue

                target = None
                # Direct call: E8 rel32
                if insn.bytes[0] == 0xE8 and len(insn.bytes) == 5:
                    rel32 = struct.unpack_from("<i", bytes(insn.bytes), 1)[0]
                    target = insn.address + 5 + rel32

                # Indirect call via IAT: FF 15 disp32
                elif len(insn.bytes) >= 6 and insn.bytes[0] == 0xFF and insn.bytes[1] == 0x15:
                    disp32 = struct.unpack_from("<i", bytes(insn.bytes), 2)[0]
                    iat_rva = insn.address + 6 + disp32
                    if iat_rva in iat_map:
                        target = iat_rva

                if target is not None and target in graph.functions:
                    if target not in fn.calls:
                        fn.calls.append(target)
                    callee = graph.functions[target]
                    if fn_addr not in callee.called_by:
                        callee.called_by.append(fn_addr)

        # Name the entry point
        if entry_rva in graph.functions and not graph.functions[entry_rva].name.startswith("sub_"):
            pass  # already named
        elif entry_rva in graph.functions:
            graph.functions[entry_rva].name = "EntryPoint"

        return graph

    def _scan_calls_raw(
        self,
        code: bytes,
        sec_rva: int,
        func_starts: set[int],
        iat_map: dict[int, tuple[str, str]],
    ) -> None:
        """Fallback call scanning without capstone (raw byte matching)."""
        call_targets: set[int] = set()

        # Scan for E8 rel32
        i = 0
        while i < len(code) - 4:
            if code[i] == 0xE8:
                rel32 = struct.unpack_from("<i", code, i + 1)[0]
                target = sec_rva + i + 5 + rel32
                if sec_rva <= target < sec_rva + len(code):
                    call_targets.add(target)
                i += 5
            else:
                i += 1

        func_starts |= call_targets

        # Create function entries
        sorted_starts = sorted(func_starts)
        for idx, start_rva in enumerate(sorted_starts):
            if start_rva in self.functions and self.functions[start_rva].is_import:
                continue
            end_rva = sorted_starts[idx + 1] if idx + 1 < len(sorted_starts) else sec_rva + len(code)
            size = end_rva - start_rva
            if start_rva not in self.functions:
                self.functions[start_rva] = Function(
                    address=start_rva, name=f"sub_{start_rva:X}", size=size
                )
            else:
                self.functions[start_rva].size = size

        # Map calls within each function
        for fn_addr in sorted(f for f in self.functions if not self.functions[f].is_import):
            fn = self.functions[fn_addr]
            if fn.size <= 0:
                continue
            offset = fn_addr - sec_rva
            if offset < 0 or offset >= len(code):
                continue
            end = min(offset + fn.size, len(code))

            j = offset
            while j < end - 4:
                # E8 rel32
                if code[j] == 0xE8:
                    rel32 = struct.unpack_from("<i", code, j + 1)[0]
                    target = sec_rva + j + 5 + rel32
                    if target in self.functions and target not in fn.calls:
                        fn.calls.append(target)
                        self.functions[target].called_by.append(fn_addr)
                    j += 5
                    continue
                # FF 15 disp32 (IAT call)
                if j < end - 5 and code[j] == 0xFF and code[j + 1] == 0x15:
                    disp32 = struct.unpack_from("<i", code, j + 2)[0]
                    iat_rva = sec_rva + j + 6 + disp32
                    if iat_rva in self.functions and iat_rva not in fn.calls:
                        fn.calls.append(iat_rva)
                        self.functions[iat_rva].called_by.append(fn_addr)
                    j += 6
                    continue
                j += 1

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------
    def roots(self) -> list[Function]:
        """Functions with no callers (entry points)."""
        return [f for f in self.functions.values() if not f.called_by and not f.is_import]

    def leaves(self) -> list[Function]:
        """Functions that don't call anything (leaf functions or imports)."""
        return [f for f in self.functions.values() if not f.calls]

    def reachable_from(self, addr: int) -> set[int]:
        """BFS from addr, return all reachable function addresses."""
        if addr not in self.functions:
            return set()
        visited: set[int] = set()
        queue = deque([addr])
        while queue:
            cur = queue.popleft()
            if cur in visited:
                continue
            visited.add(cur)
            if cur in self.functions:
                for callee in self.functions[cur].calls:
                    if callee not in visited:
                        queue.append(callee)
        return visited

    def path(self, src: int, dst: int) -> list[int] | None:
        """Shortest path between two functions (BFS)."""
        if src not in self.functions or dst not in self.functions:
            return None
        if src == dst:
            return [src]

        visited: set[int] = {src}
        queue: deque[list[int]] = deque([[src]])
        while queue:
            current_path = queue.popleft()
            node = current_path[-1]
            if node not in self.functions:
                continue
            for neighbor in self.functions[node].calls:
                if neighbor == dst:
                    return current_path + [dst]
                if neighbor not in visited:
                    visited.add(neighbor)
                    queue.append(current_path + [neighbor])
        return None

    # ------------------------------------------------------------------
    # Serialization
    # ------------------------------------------------------------------
    def to_dict(self) -> dict:
        """JSON-serializable representation of the entire call graph."""
        return {
            "functions": {
                hex(addr): fn.to_dict() for addr, fn in self.functions.items()
            },
            "stats": {
                "total_functions": len(self.functions),
                "imports": sum(1 for f in self.functions.values() if f.is_import),
                "roots": len(self.roots()),
                "leaves": len(self.leaves()),
            },
        }
