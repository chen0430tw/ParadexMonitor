"""
Data flow analysis -- track argument values passed to API calls.

Uses capstone to disassemble backward from call sites and track
register assignments for the x64 Microsoft calling convention and
stack arguments for x86 cdecl/stdcall. Register-based x86 conventions
(thiscall/fastcall) are not inferred.
"""
from __future__ import annotations

import re

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ppm_engine.topology.callgraph import CallGraph

try:
    import capstone
except ImportError:
    capstone = None


# x64 Microsoft calling convention: first 4 args in registers
_ARG_REGS = ["rcx", "rdx", "r8", "r9"]
_ARG_REGS_32 = ["ecx", "edx", "r8d", "r9d"]

# Register aliases (sub-register -> canonical 64-bit)
_REG_CANON = {
    "eax": "rax", "ax": "rax", "al": "rax",
    "ebx": "rbx", "bx": "rbx", "bl": "rbx",
    "ecx": "rcx", "cx": "rcx", "cl": "rcx",
    "edx": "rdx", "dx": "rdx", "dl": "rdx",
    "esi": "rsi", "si": "rsi",
    "edi": "rdi", "di": "rdi",
    "r8d": "r8", "r8w": "r8", "r8b": "r8",
    "r9d": "r9", "r9w": "r9", "r9b": "r9",
    "r10d": "r10", "r11d": "r11", "r12d": "r12",
    "r13d": "r13", "r14d": "r14", "r15d": "r15",
}


def _canonicalize(reg: str) -> str:
    return _REG_CANON.get(reg.strip().lower(), reg.strip().lower())


def track_arguments(
    graph: CallGraph,
    target_addr: int,
    raw_text: bytes | None = None,
    text_base: int = 0,
) -> dict[int, list[dict]]:
    """Track argument values passed to a specific API at each call site.

    Disassembles backward from each call site to *target_addr* and
    resolves x64 register arguments or x86 stack arguments.

    Parameters:
        graph: The call graph containing function/call information.
        target_addr: Address of the target function/import.
        raw_text: Raw bytes of the .text section (for disassembly).
        text_base: RVA of the .text section start.

    Returns:
        ``{call_site_addr: [{"arg": 0, "reg": "rcx", "value": "0x200", "source": "immediate"}, ...]}``
    """
    if capstone is None:
        return {}

    if target_addr not in graph.functions:
        return {}

    fn = graph.functions[target_addr]
    if not fn.called_by:
        return {}

    if raw_text is None:
        return {}

    bitness = getattr(graph, "bitness", 64)
    mode = capstone.CS_MODE_32 if bitness == 32 else capstone.CS_MODE_64
    md = capstone.Cs(capstone.CS_ARCH_X86, mode)
    md.detail = False  # we parse operands manually for speed

    results: dict[int, list[dict]] = {}

    for caller_addr in fn.called_by:
        caller_fn = graph.functions.get(caller_addr)
        if caller_fn is None or caller_fn.is_import:
            continue

        # Find call sites to target within this caller
        caller_size = caller_fn.size or 0x400
        offset = caller_addr - text_base
        if offset < 0 or offset >= len(raw_text):
            continue

        func_bytes = raw_text[offset:offset + min(caller_size, 0x1000)]
        insns = list(md.disasm(func_bytes, caller_addr))

        # Find all call instructions targeting target_addr
        for i, insn in enumerate(insns):
            if insn.mnemonic != "call":
                continue

            # Check if this call targets our function
            call_target = _parse_call_target(insn, target_addr, graph)
            if call_target != target_addr:
                continue

            # Walk backward from the call site to resolve arg registers
            args = (_resolve_stack_args_backward(insns[:i]) if bitness == 32
                    else _resolve_args_backward(insns[:i], insn.address))
            if args:
                results[insn.address] = args

    return results


def _parse_call_target(insn, expected: int, graph: CallGraph) -> int:
    """Parse call instruction's target address."""
    op = insn.op_str.strip()

    # E8 rel32: direct call
    try:
        target = int(op, 0)
        return target
    except (ValueError, TypeError):
        pass

    # x86 uses an absolute VA for the IAT slot, whereas graph keys are RVAs.
    if getattr(graph, "bitness", 64) == 32:
        match = re.fullmatch(r"(?:dword ptr )?\[(0x[0-9a-f]+)\]", op.lower())
        if match:
            slot = int(match.group(1), 0) - graph.image_base
            fn = graph.functions.get(slot)
            if fn and fn.is_import:
                return slot

    if "rip" in op.lower():
        disp = _extract_rip_disp(op)
        if disp is not None:
            slot = insn.address + insn.size + disp
            fn = graph.functions.get(slot)
            if fn and fn.is_import:
                return slot

    return 0


def _resolve_args_backward(insns: list, call_addr: int) -> list[dict]:
    """Walk backward from a call site to resolve argument register values.

    Tracks assignments to rcx, rdx, r8, r9 in the window before the call.
    Stops at the first assignment found for each register (most recent wins).
    """
    args: list[dict] = []
    found: set[str] = set()
    target_regs = set(_ARG_REGS + _ARG_REGS_32)

    # Walk backward through instructions (up to 30 instructions before call)
    window = insns[-30:] if len(insns) > 30 else insns

    for insn in reversed(window):
        if len(found) >= 4:
            break

        mn = insn.mnemonic.lower()
        ops = insn.op_str

        if mn == "mov":
            parts = [p.strip() for p in ops.split(",", 1)]
            if len(parts) != 2:
                continue
            dst, src = parts

            dst_canon = _canonicalize(dst)
            if dst_canon not in _ARG_REGS or dst_canon in found:
                continue

            found.add(dst_canon)
            arg_idx = _ARG_REGS.index(dst_canon)

            # Classify source
            value, source = _classify_source(src)
            args.append({
                "arg": arg_idx,
                "reg": dst_canon,
                "value": value,
                "source": source,
            })

        elif mn == "lea":
            parts = [p.strip() for p in ops.split(",", 1)]
            if len(parts) != 2:
                continue
            dst, src = parts

            dst_canon = _canonicalize(dst)
            if dst_canon not in _ARG_REGS or dst_canon in found:
                continue

            found.add(dst_canon)
            arg_idx = _ARG_REGS.index(dst_canon)

            # LEA typically loads an address
            if "rip" in src.lower():
                # RIP-relative: compute target address
                disp = _extract_rip_disp(src)
                if disp:
                    target = insn.address + insn.size + disp
                    args.append({
                        "arg": arg_idx,
                        "reg": dst_canon,
                        "value": f"0x{target:X}",
                        "source": "rip_relative",
                    })
                else:
                    args.append({
                        "arg": arg_idx,
                        "reg": dst_canon,
                        "value": src,
                        "source": "address",
                    })
            else:
                args.append({
                    "arg": arg_idx,
                    "reg": dst_canon,
                    "value": f"&{src}",
                    "source": "address",
                })

        elif mn == "xor":
            parts = [p.strip() for p in ops.split(",")]
            if len(parts) == 2 and _canonicalize(parts[0]) == _canonicalize(parts[1]):
                dst_canon = _canonicalize(parts[0])
                if dst_canon in _ARG_REGS and dst_canon not in found:
                    found.add(dst_canon)
                    arg_idx = _ARG_REGS.index(dst_canon)
                    args.append({
                        "arg": arg_idx,
                        "reg": dst_canon,
                        "value": "0",
                        "source": "zero",
                    })

        # Stop if we hit another call (registers may be clobbered)
        elif mn == "call":
            break

    args.sort(key=lambda a: a["arg"])
    return args


def _classify_source(src: str) -> tuple[str, str]:
    """Classify a MOV source operand."""
    s = src.strip()

    # Immediate value
    if s.startswith("0x") or s.startswith("-0x") or s.lstrip("-").isdigit():
        return s, "immediate"

    # Memory reference
    if "[" in s:
        return s, "memory"

    # Register
    canon = _canonicalize(s)
    if canon.startswith("r") or canon in ("rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp"):
        return canon, "register"

    return s, "unknown"


def _extract_rip_disp(operand: str) -> int | None:
    """Extract displacement from [rip + 0xNNNN] operand."""
    op = operand.lower()
    if "rip" not in op:
        return None
    sign = 1
    if "-" in op and "rip" in op.split("-")[0]:
        sign = -1
    for part in op.replace("+", " ").replace("-", " ").split():
        part = part.strip().rstrip("]").lstrip("[")
        if part == "rip" or "ptr" in part or "qword" in part:
            continue
        try:
            return sign * int(part, 0)
        except ValueError:
            continue
    return None


def track_all_interesting(
    graph: CallGraph,
    raw_text: bytes,
    text_base: int,
    api_names: list[str] | None = None,
) -> dict[str, dict[int, list[dict]]]:
    """Track arguments for all interesting API calls in the binary.

    Parameters:
        graph: Call graph.
        raw_text: .text section bytes.
        text_base: .text section RVA.
        api_names: List of API names to track. If None, tracks a default set
                   of security-relevant APIs.

    Returns:
        ``{"ObOpenObjectByPointer": {0x1234: [{"arg": 0, ...}]}, ...}``
    """
    if api_names is None:
        api_names = [
            "ObOpenObjectByPointer",
            "ObRegisterCallbacks",
            "CmRegisterCallbackEx",
            "ZwOpenProcess",
            "ZwTerminateProcess",
            "ZwAllocateVirtualMemory",
            "KeInsertQueueApc",
            "PsLookupProcessByProcessId",
            "MmGetSystemRoutineAddress",
        ]

    results: dict[str, dict[int, list[dict]]] = {}

    for addr, fn in graph.functions.items():
        if fn.is_import and fn.import_name in api_names:
            tracked = track_arguments(graph, addr, raw_text, text_base)
            if tracked:
                results[fn.import_name] = tracked

    return results


def _resolve_stack_args_backward(insns: list) -> list[dict]:
    """Best-effort x86 cdecl/stdcall arguments; offsets are relative to pre-call ESP.

    Stop at calls and branches. Register-based thiscall/fastcall is not inferred.
    """
    slots = {}
    delta = 0
    window_start = max(0, len(insns) - 30)

    def value_at(operand, before):
        operand = operand.strip()
        seen = set()
        for prev in reversed(insns[window_start:before]):
            if prev.mnemonic == "call" or prev.mnemonic.startswith("j"):
                break
            parts = [p.strip() for p in prev.op_str.split(",", 1)]
            if len(parts) != 2 or parts[0] != operand:
                continue
            if prev.mnemonic == "xor" and parts[0] == parts[1]:
                return "0", "zero"
            if prev.mnemonic == "lea":
                return "&" + parts[1], "address"
            if prev.mnemonic != "mov":
                break
            operand = parts[1]
            if operand in seen:
                break
            seen.add(operand)
        if re.fullmatch(r"e(?:ax|bx|cx|dx|si|di|bp|sp)", operand):
            return operand, "register"
        return _classify_source(operand)

    for index in range(len(insns) - 1, window_start - 1, -1):
        insn = insns[index]
        mn, ops = insn.mnemonic, insn.op_str
        if mn == "call" or mn.startswith("j") or mn.startswith("ret") or mn == "leave":
            break
        if mn == "push":
            if ops == "ebp":  # Do not report the frame pointer as an argument.
                break
            if delta >= 0 and delta % 4 == 0 and delta < 64 and delta not in slots:
                slots[delta] = value_at(ops, index)
            delta += 4
        elif mn == "pop":
            delta -= 4
        elif mn in ("sub", "add"):
            parts = [p.strip() for p in ops.split(",", 1)]
            if len(parts) == 2 and parts[0] == "esp":
                try:
                    delta += int(parts[1], 0) * (1 if mn == "sub" else -1)
                except ValueError:
                    break
        elif mn == "mov":
            parts = [p.strip() for p in ops.split(",", 1)]
            if len(parts) != 2:
                continue
            if parts[0] in ("esp", "ebp"):
                break
            match = re.fullmatch(r"(?:dword ptr )?\[esp(?: \+ (0x[0-9a-f]+|[0-9]+))?\]", parts[0])
            if match:
                offset = delta + int(match.group(1) or "0", 0)
                if 0 <= offset < 64 and offset % 4 == 0 and offset not in slots:
                    slots[offset] = value_at(parts[1], index)

    args = []
    for offset in range(0, 64, 4):
        if offset not in slots:
            break
        value, source = slots[offset]
        args.append({"arg": offset // 4, "reg": f"[esp+0x{offset:X}]",
                     "value": value, "source": source})
    return args
