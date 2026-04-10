"""
Detect APC injection pattern.

APC (Asynchronous Procedure Call) injection is used by kernel drivers to
execute code in the context of a target process. The typical pattern is:

    1. PsSetCreateProcessNotifyRoutine  — get notified when target starts
    2. ZwOpenProcess / ObOpenObjectByPointer — get handle to target
    3. ZwAllocateVirtualMemory — allocate memory in target
    4. KeInitializeApc — set up APC structure
    5. KeInsertQueueApc — queue APC for execution in target

Dynamic resolution via MmGetSystemRoutineAddress may replace direct imports.
"""
from __future__ import annotations

from .base import Pattern, PatternMatch


# APIs involved in the APC injection lifecycle
_NOTIFY_APIS = {
    "PsSetCreateProcessNotifyRoutine",
    "PsSetCreateProcessNotifyRoutineEx",
    "PsSetCreateProcessNotifyRoutineEx2",
    "PsSetCreateThreadNotifyRoutine",
    "PsSetLoadImageNotifyRoutine",
}

_PROCESS_ACCESS_APIS = {
    "ZwOpenProcess",
    "NtOpenProcess",
    "ObOpenObjectByPointer",
    "PsLookupProcessByProcessId",
}

_MEMORY_APIS = {
    "ZwAllocateVirtualMemory",
    "NtAllocateVirtualMemory",
    "ZwWriteVirtualMemory",
    "NtWriteVirtualMemory",
    "MmCopyVirtualMemory",
}

_APC_APIS = {
    "KeInitializeApc",
    "KeInsertQueueApc",
}

_DYNAMIC_RESOLVE = {
    "MmGetSystemRoutineAddress",
}


class ApcInjectPattern(Pattern):

    @property
    def name(self) -> str:
        return "apc_inject"

    def scan(self, adapter, callgraph=None, depgraph=None) -> list[PatternMatch]:
        matches: list[PatternMatch] = []

        imports = adapter.imports()
        all_funcs: set[str] = set()
        for funcs in imports.values():
            all_funcs.update(funcs)

        # Check which stages of the APC injection chain are present
        has_notify = bool(all_funcs & _NOTIFY_APIS)
        has_process_access = bool(all_funcs & _PROCESS_ACCESS_APIS)
        has_memory = bool(all_funcs & _MEMORY_APIS)
        has_apc = bool(all_funcs & _APC_APIS)
        has_dynamic = bool(all_funcs & _DYNAMIC_RESOLVE)

        # APC APIs are the core indicator
        if not has_apc and not has_dynamic:
            return matches

        # Scan IAT call sites to locate the actual APC calls
        iat_calls = adapter.iat_calls()
        apc_call_sites: list[dict] = []
        for call in iat_calls:
            if call["target_func"] in _APC_APIS:
                apc_call_sites.append(call)

        # Calculate confidence based on how many stages are present
        stage_count = sum([has_notify, has_process_access, has_memory, has_apc])
        if has_apc:
            base_confidence = 0.5 + (stage_count - 1) * 0.15
        else:
            # Only dynamic resolution, no direct APC imports
            base_confidence = 0.3

        # Check for dynamic resolution of APC APIs (higher sophistication)
        dynamic_apc = False
        if has_dynamic:
            strings = adapter.strings(min_len=4)
            for s in strings:
                val = s.get("value", "")
                if val in _APC_APIS or val in _MEMORY_APIS or val in _PROCESS_ACCESS_APIS:
                    dynamic_apc = True
                    break

        if dynamic_apc:
            base_confidence = min(base_confidence + 0.1, 1.0)

        # Build details
        found_apis = {
            "notify": sorted(all_funcs & _NOTIFY_APIS),
            "process_access": sorted(all_funcs & _PROCESS_ACCESS_APIS),
            "memory": sorted(all_funcs & _MEMORY_APIS),
            "apc": sorted(all_funcs & _APC_APIS),
            "dynamic_resolve": sorted(all_funcs & _DYNAMIC_RESOLVE),
        }

        # Build chain description
        chain_parts: list[str] = []
        if has_notify:
            chain_parts.append("process/thread notification")
        if has_process_access:
            chain_parts.append("target process access")
        if has_memory:
            chain_parts.append("remote memory allocation/write")
        if has_apc:
            chain_parts.append("APC queue injection")
        if dynamic_apc:
            chain_parts.append("dynamic API resolution (evasion)")

        chain_desc = " -> ".join(chain_parts)

        location = apc_call_sites[0]["rva"] if apc_call_sites else 0

        desc = (
            f"APC injection pattern detected ({stage_count}/4 stages present). "
            f"Chain: {chain_desc}. "
        )
        if has_apc and has_notify:
            desc += (
                "The driver monitors process creation and injects code via "
                "APC into target processes."
            )
        elif has_apc:
            desc += "APC primitives present but trigger mechanism unclear."
        elif dynamic_apc:
            desc += (
                "APC APIs resolved dynamically via MmGetSystemRoutineAddress "
                "(import hiding)."
            )

        matches.append(PatternMatch(
            pattern_name=self.name,
            confidence=round(min(base_confidence, 1.0), 2),
            location=location,
            details={
                "apis": found_apis,
                "call_sites": [
                    {"rva": f"0x{c['rva']:X}", "func": c["target_func"]}
                    for c in apc_call_sites
                ],
                "stages_present": stage_count,
                "dynamic_resolution": dynamic_apc,
                "chain": chain_desc,
            },
            description=desc,
        ))

        return matches
