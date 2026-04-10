"""
Convert disassembly (capstone instruction list) to C-like pseudo-code.

This is a *best-effort* lifter targeting x86-64 Windows kernel drivers.
It handles the most common patterns seen in kernel callbacks:

    - Function prologue / epilogue
    - IAT calls via FF 15 (call [rip+disp32])
    - Register assignments (mov, xor, lea)
    - Comparisons + conditional jumps -> if/else blocks
    - Stack variable references
"""
from __future__ import annotations

from typing import Optional


class PseudoCodeGenerator:
    """Lift disassembly to C-like pseudo-code."""

    # Known API signatures for readable output
    API_SIGNATURES: dict[str, str] = {
        "ObRegisterCallbacks":
            "NTSTATUS ObRegisterCallbacks(OB_CALLBACK_REGISTRATION* reg, PVOID* handle)",
        "CmRegisterCallbackEx":
            "NTSTATUS CmRegisterCallbackEx(PEX_CALLBACK_FUNCTION fn, PUNICODE_STRING alt, "
            "PVOID drv, PVOID ctx, PLARGE_INTEGER cookie)",
        "PsGetProcessId":
            "HANDLE PsGetProcessId(PEPROCESS proc)",
        "ObOpenObjectByPointer":
            "NTSTATUS ObOpenObjectByPointer(PVOID obj, ULONG flags, PACCESS_STATE as, "
            "ACCESS_MASK access, POBJECT_TYPE type, KPROCESSOR_MODE mode, PHANDLE handle)",
        "PsSetCreateProcessNotifyRoutine":
            "NTSTATUS PsSetCreateProcessNotifyRoutine(PCREATE_PROCESS_NOTIFY_ROUTINE fn, "
            "BOOLEAN remove)",
        "ZwTerminateProcess":
            "NTSTATUS ZwTerminateProcess(HANDLE proc, NTSTATUS status)",
        "KeInsertQueueApc":
            "BOOLEAN KeInsertQueueApc(PRKAPC apc, PVOID a1, PVOID a2, KPRIORITY inc)",
        "RtlCompareUnicodeString":
            "LONG RtlCompareUnicodeString(PCUNICODE_STRING s1, PCUNICODE_STRING s2, BOOLEAN ci)",
        "ZwOpenProcess":
            "NTSTATUS ZwOpenProcess(PHANDLE handle, ACCESS_MASK access, "
            "POBJECT_ATTRIBUTES oa, PCLIENT_ID cid)",
        "KeInitializeApc":
            "VOID KeInitializeApc(PRKAPC apc, PRKTHREAD thread, "
            "KAPC_ENVIRONMENT env, PKKERNEL_ROUTINE kr, PKRUNDOWN_ROUTINE rr, "
            "PKNORMAL_ROUTINE nr, KPROCESSOR_MODE mode, PVOID ctx)",
        "ZwAllocateVirtualMemory":
            "NTSTATUS ZwAllocateVirtualMemory(HANDLE proc, PVOID* base, "
            "ULONG_PTR zero, PSIZE_T size, ULONG type, ULONG protect)",
        "MmGetSystemRoutineAddress":
            "PVOID MmGetSystemRoutineAddress(PUNICODE_STRING name)",
        "ExAllocatePoolWithTag":
            "PVOID ExAllocatePoolWithTag(POOL_TYPE type, SIZE_T size, ULONG tag)",
        "ExFreePoolWithTag":
            "VOID ExFreePoolWithTag(PVOID ptr, ULONG tag)",
        "IoCreateDevice":
            "NTSTATUS IoCreateDevice(PDRIVER_OBJECT drv, ULONG ext, "
            "PUNICODE_STRING name, DEVICE_TYPE type, ULONG chars, BOOLEAN excl, "
            "PDEVICE_OBJECT* dev)",
    }

    # x64 calling convention argument registers (Microsoft)
    _ARG_REGS_64 = ("rcx", "rdx", "r8", "r9")
    _ARG_REGS_32 = ("ecx", "edx", "r8d", "r9d")

    # Condition code -> C operator (for jcc instructions)
    _JCC_MAP: dict[str, str] = {
        "je": "==", "jz": "==",
        "jne": "!=", "jnz": "!=",
        "jg": ">", "jnle": ">",
        "jge": ">=", "jnl": ">=",
        "jl": "<", "jnge": "<",
        "jle": "<=", "jng": "<=",
        "ja": ">", "jnbe": ">",       # unsigned
        "jae": ">=", "jnb": ">=",     # unsigned
        "jb": "<", "jnae": "<",       # unsigned
        "jbe": "<=", "jna": "<=",     # unsigned
        "js": "< 0",
        "jns": ">= 0",
    }

    def generate(
        self,
        func_addr: int,
        disasm_lines: list,
        imports: dict,
        strings: dict,
    ) -> str:
        """Generate C-like pseudo-code from a list of capstone-style instructions.

        Parameters
        ----------
        func_addr : int
            RVA of the function start.
        disasm_lines : list
            Each element is an object/dict with at least:
                .mnemonic (str), .op_str (str), .address (int)
            Capstone Instruction objects or dicts are both accepted.
        imports : dict
            RVA -> function name mapping (IAT resolved).
        strings : dict
            RVA -> string value mapping.

        Returns
        -------
        str
            C-like pseudo-code.
        """
        if not disasm_lines:
            return f"// Empty function at 0x{func_addr:X}\nvoid sub_{func_addr:X}(void) {{}}"

        lines: list[str] = []
        indent = 1
        reg_state: dict[str, str] = {}  # track register assignments
        last_cmp: Optional[tuple[str, str]] = None  # (left, right) from last cmp
        in_function = False
        branch_targets: set[int] = set()

        # Pre-scan for branch targets (to identify if/else block ends)
        for insn in disasm_lines:
            mn = self._get_mnemonic(insn)
            if mn.startswith("j") and mn != "jmp":
                target = self._parse_jump_target(insn)
                if target is not None:
                    branch_targets.add(target)

        for i, insn in enumerate(disasm_lines):
            mn = self._get_mnemonic(insn)
            ops = self._get_op_str(insn)
            addr = self._get_address(insn)

            # Emit label if this address is a branch target
            if addr in branch_targets and in_function:
                # Close any pending if-block
                if indent > 1:
                    indent -= 1
                    lines.append(f"{'    ' * indent}}}")

            # ---- Function prologue ----
            if not in_function and mn in ("push", "sub") and i < 3:
                if mn == "push" and "rbp" in ops:
                    # push rbp — typical prologue
                    continue
                if mn == "sub" and "rsp" in ops:
                    stack_size = self._parse_imm(ops.split(",")[-1].strip())
                    lines.append(f"// Function at 0x{func_addr:X}")
                    lines.append(f"// Stack frame: {stack_size} bytes")
                    lines.append(f"void sub_{func_addr:X}()")
                    lines.append("{")
                    in_function = True
                    continue
                if mn == "push" and i == 0:
                    # Single push at start — still prologue
                    continue

            if not in_function and i == 0:
                lines.append(f"void sub_{func_addr:X}()")
                lines.append("{")
                in_function = True

            pad = "    " * indent

            # ---- xor reg, reg -> reg = 0 ----
            if mn == "xor":
                parts = [p.strip() for p in ops.split(",")]
                if len(parts) == 2 and self._reg_base(parts[0]) == self._reg_base(parts[1]):
                    canonical = parts[0]
                    reg_state[canonical] = "0"
                    lines.append(f"{pad}{canonical} = 0;")
                    continue

            # ---- mov reg, imm ----
            if mn == "mov":
                parts = [p.strip() for p in ops.split(",", 1)]
                if len(parts) == 2:
                    dst, src = parts
                    # mov reg, imm
                    if self._is_register(dst) and self._looks_like_imm(src):
                        val = self._format_imm(src, strings)
                        reg_state[dst] = val
                        lines.append(f"{pad}{dst} = {val};")
                        continue
                    # mov reg, reg
                    if self._is_register(dst) and self._is_register(src):
                        src_val = reg_state.get(src, src)
                        reg_state[dst] = src_val
                        lines.append(f"{pad}{dst} = {src_val};")
                        continue
                    # mov [mem], reg or mov reg, [mem]
                    lines.append(f"{pad}{dst} = {src};")
                    continue

            # ---- lea reg, [rip+disp] -> reg = &data/string ----
            if mn == "lea":
                parts = [p.strip() for p in ops.split(",", 1)]
                if len(parts) == 2:
                    dst, src = parts
                    resolved = self._resolve_rip_ref(src, addr, strings, imports)
                    if resolved:
                        reg_state[dst] = resolved
                        lines.append(f"{pad}{dst} = {resolved};")
                    else:
                        reg_state[dst] = f"&{src}"
                        lines.append(f"{pad}{dst} = &{src};")
                    continue

            # ---- cmp ----
            if mn in ("cmp", "test"):
                parts = [p.strip() for p in ops.split(",")]
                if len(parts) == 2:
                    left = reg_state.get(parts[0], parts[0])
                    right = reg_state.get(parts[1], parts[1])
                    if mn == "test" and parts[0] == parts[1]:
                        last_cmp = (left, "0")
                    else:
                        last_cmp = (left, right)
                continue

            # ---- jcc -> if (...) ----
            if mn in self._JCC_MAP and mn != "jmp":
                op_sym = self._JCC_MAP[mn]
                if last_cmp:
                    left, right = last_cmp
                    if op_sym in ("< 0", ">= 0"):
                        cond = f"{left} {op_sym}"
                    else:
                        cond = f"{left} {op_sym} {right}"
                else:
                    cond = f"/* {mn} */"
                lines.append(f"{pad}if ({cond}) {{")
                indent += 1
                last_cmp = None
                continue

            # ---- jmp -> goto / else ----
            if mn == "jmp":
                target = self._parse_jump_target(insn)
                if target is not None:
                    lines.append(f"{pad}goto loc_{target:X};")
                else:
                    lines.append(f"{pad}goto {ops};")
                continue

            # ---- call [rip+disp] (IAT) or call imm ----
            if mn == "call":
                api_name = self._resolve_call(ops, addr, imports)
                if api_name:
                    args = self._build_arg_string(api_name, reg_state)
                    lines.append(f"{pad}{api_name}({args});")
                else:
                    # Direct call to sub-address
                    target = ops.strip()
                    lines.append(f"{pad}sub_{target}();")
                reg_state.clear()  # callee may clobber volatile regs
                continue

            # ---- ret -> closing ----
            if mn in ("ret", "retn"):
                # Check if eax/rax has a known value
                ret_val = reg_state.get("eax", reg_state.get("rax", None))
                if ret_val is not None and ret_val != "0":
                    lines.append(f"{pad}return {ret_val};")
                elif ret_val == "0":
                    lines.append(f"{pad}return STATUS_SUCCESS;  // 0")
                else:
                    lines.append(f"{pad}return;")
                continue

            # ---- nop ----
            if mn == "nop" or mn.startswith("nop"):
                continue

            # ---- and reg, imm -> bitmask (handle stripping pattern) ----
            if mn == "and":
                parts = [p.strip() for p in ops.split(",")]
                if len(parts) == 2:
                    dst, src = parts
                    val = self._format_imm(src, strings)
                    lines.append(f"{pad}{dst} &= {val};")
                    continue

            # ---- or reg, imm ----
            if mn == "or":
                parts = [p.strip() for p in ops.split(",")]
                if len(parts) == 2:
                    dst, src = parts
                    val = self._format_imm(src, strings)
                    lines.append(f"{pad}{dst} |= {val};")
                    continue

            # ---- add / sub ----
            if mn in ("add", "sub"):
                parts = [p.strip() for p in ops.split(",")]
                if len(parts) == 2:
                    dst, src = parts
                    op = "+" if mn == "add" else "-"
                    val = self._format_imm(src, strings)
                    lines.append(f"{pad}{dst} {op}= {val};")
                    continue

            # ---- push / pop (not prologue) ----
            if mn == "push" and in_function:
                lines.append(f"{pad}// push {ops}")
                continue
            if mn == "pop" and in_function:
                lines.append(f"{pad}// pop {ops}")
                continue

            # ---- fallback: emit as comment ----
            if in_function:
                lines.append(f"{pad}// {mn} {ops}")

        # Close any open braces
        while indent > 1:
            indent -= 1
            lines.append(f"{'    ' * indent}}}")

        if in_function:
            lines.append("}")

        if not in_function:
            # Never opened the function (no prologue detected)
            return (
                f"void sub_{func_addr:X}()\n{{\n"
                + "\n".join(f"    // {self._get_mnemonic(i)} {self._get_op_str(i)}"
                            for i in disasm_lines)
                + "\n}"
            )

        return "\n".join(lines)

    # ---------------------------------------------------------------
    # Instruction access helpers (support both capstone objects & dicts)
    # ---------------------------------------------------------------

    @staticmethod
    def _get_mnemonic(insn) -> str:
        if isinstance(insn, dict):
            return insn.get("mnemonic", "")
        return getattr(insn, "mnemonic", "")

    @staticmethod
    def _get_op_str(insn) -> str:
        if isinstance(insn, dict):
            return insn.get("op_str", "")
        return getattr(insn, "op_str", "")

    @staticmethod
    def _get_address(insn) -> int:
        if isinstance(insn, dict):
            return insn.get("address", 0)
        return getattr(insn, "address", 0)

    # ---------------------------------------------------------------
    # Resolution helpers
    # ---------------------------------------------------------------

    @staticmethod
    def _is_register(s: str) -> bool:
        regs = {
            "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
            "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
            "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp",
            "r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d",
            "al", "bl", "cl", "dl", "ah", "bh", "ch", "dh",
            "r8b", "r9b", "r10b", "r11b",
            "ax", "bx", "cx", "dx",
            "r8w", "r9w", "r10w", "r11w",
        }
        return s.lower().strip() in regs

    @staticmethod
    def _reg_base(reg: str) -> str:
        """Map sub-registers to their base: eax->rax, r8d->r8, etc."""
        r = reg.strip().lower()
        mapping = {
            "eax": "rax", "ax": "rax", "al": "rax", "ah": "rax",
            "ebx": "rbx", "bx": "rbx", "bl": "rbx", "bh": "rbx",
            "ecx": "rcx", "cx": "rcx", "cl": "rcx", "ch": "rcx",
            "edx": "rdx", "dx": "rdx", "dl": "rdx", "dh": "rdx",
            "esi": "rsi", "si": "rsi", "sil": "rsi",
            "edi": "rdi", "di": "rdi", "dil": "rdi",
            "ebp": "rbp", "bp": "rbp", "bpl": "rbp",
            "esp": "rsp", "sp": "rsp", "spl": "rsp",
            "r8d": "r8", "r8w": "r8", "r8b": "r8",
            "r9d": "r9", "r9w": "r9", "r9b": "r9",
            "r10d": "r10", "r10w": "r10", "r10b": "r10",
            "r11d": "r11", "r11w": "r11", "r11b": "r11",
            "r12d": "r12", "r12w": "r12", "r12b": "r12",
            "r13d": "r13", "r13w": "r13", "r13b": "r13",
            "r14d": "r14", "r14w": "r14", "r14b": "r14",
            "r15d": "r15", "r15w": "r15", "r15b": "r15",
        }
        return mapping.get(r, r)

    @staticmethod
    def _looks_like_imm(s: str) -> bool:
        s = s.strip()
        if s.startswith("0x") or s.startswith("-0x"):
            return True
        if s.lstrip("-").isdigit():
            return True
        return False

    @staticmethod
    def _parse_imm(s: str) -> str:
        s = s.strip()
        try:
            if s.startswith("0x") or s.startswith("-0x"):
                return s
            v = int(s, 0)
            if v > 255:
                return f"0x{v:X}"
            return str(v)
        except (ValueError, TypeError):
            return s

    def _format_imm(self, s: str, strings: dict) -> str:
        s = s.strip()
        try:
            v = int(s, 0)
            # Check if this references a string
            if v in strings:
                return f'"{strings[v]}"'
            if v > 255:
                return f"0x{v:X}"
            return str(v)
        except (ValueError, TypeError):
            return s

    def _resolve_rip_ref(self, operand: str, insn_addr: int,
                         strings: dict, imports: dict) -> Optional[str]:
        """Try to resolve [rip+disp] to a string or import name."""
        # Extract displacement from patterns like [rip + 0x1234]
        op = operand.strip().lower()
        if "rip" not in op:
            return None

        # Parse displacement
        disp = 0
        if "+" in op:
            parts = op.split("+")
            for p in parts:
                p = p.strip().rstrip("]").strip()
                if p != "rip" and not p.startswith("["):
                    try:
                        disp = int(p, 0)
                    except ValueError:
                        pass
        elif "-" in op and "rip" in op.split("-")[0]:
            parts = op.split("-")
            if len(parts) >= 2:
                try:
                    disp = -int(parts[-1].strip().rstrip("]"), 0)
                except ValueError:
                    pass

        if disp == 0:
            return None

        # RIP-relative: target = next_insn_addr + disp
        # Assume instruction is ~7 bytes (lea is typically 7)
        target_rva = insn_addr + 7 + disp

        if target_rva in strings:
            return f'&"{strings[target_rva]}"'
        if target_rva in imports:
            return f"&{imports[target_rva]}"

        return f"data_{target_rva:X}"

    def _resolve_call(self, operand: str, insn_addr: int, imports: dict) -> Optional[str]:
        """Resolve a call target to a function name."""
        op = operand.strip()

        # Direct call to known import by name match
        for rva, name in imports.items():
            if isinstance(name, str) and name in op:
                return name

        # call qword ptr [rip + disp]
        lower = op.lower()
        if "rip" in lower:
            disp = 0
            if "+" in lower:
                parts = lower.split("+")
                for p in parts:
                    p = p.strip().rstrip("]").strip()
                    if p != "rip" and "ptr" not in p and not p.startswith("[") and not p.startswith("qword"):
                        try:
                            disp = int(p, 0)
                        except ValueError:
                            pass
            if disp:
                # call is 6 bytes (FF 15 xx xx xx xx)
                target_rva = insn_addr + 6 + disp
                if target_rva in imports:
                    name = imports[target_rva]
                    if isinstance(name, tuple):
                        return name[1]  # (dll, func) tuple
                    return name

        # Direct call to absolute/relative address
        try:
            target = int(op, 0)
            if target in imports:
                name = imports[target]
                if isinstance(name, tuple):
                    return name[1]
                return name
            return f"sub_{target:X}"
        except (ValueError, TypeError):
            pass

        return None

    def _build_arg_string(self, api_name: str, reg_state: dict) -> str:
        """Build argument string from tracked register state and API signature."""
        sig = self.API_SIGNATURES.get(api_name)
        if not sig:
            # Just dump known argument registers
            args = []
            for r in self._ARG_REGS_64:
                if r in reg_state:
                    args.append(reg_state[r])
                elif r.replace("r", "e", 1) in reg_state:
                    args.append(reg_state[r.replace("r", "e", 1)])
            for r in self._ARG_REGS_32:
                if r in reg_state and reg_state[r] not in args:
                    args.append(reg_state[r])
            return ", ".join(args) if args else "..."

        # Count parameters from signature
        param_start = sig.index("(") + 1
        param_end = sig.rindex(")")
        params = [p.strip() for p in sig[param_start:param_end].split(",") if p.strip()]
        num_params = len(params)

        arg_regs = list(self._ARG_REGS_64[:min(num_params, 4)])
        arg_regs_32 = list(self._ARG_REGS_32[:min(num_params, 4)])

        args: list[str] = []
        for idx in range(num_params):
            if idx < 4:
                val = reg_state.get(arg_regs[idx],
                      reg_state.get(arg_regs_32[idx], "?"))
                args.append(val)
            else:
                args.append("/* stack */")

        return ", ".join(args)

    @staticmethod
    def _parse_jump_target(insn) -> Optional[int]:
        """Parse the jump target address from a jcc/jmp instruction."""
        if isinstance(insn, dict):
            op_str = insn.get("op_str", "")
        else:
            op_str = getattr(insn, "op_str", "")
        op_str = op_str.strip()
        try:
            return int(op_str, 0)
        except (ValueError, TypeError):
            return None
