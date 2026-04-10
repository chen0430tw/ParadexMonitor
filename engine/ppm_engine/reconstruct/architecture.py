"""
High-level architecture summary from analysis results.

Given file info, dependency graph, and chain analysis, this module
classifies the driver type and summarizes its behavior in a structured dict.
"""
from __future__ import annotations

from typing import Optional


# Known suspicious string patterns
_SUSPICIOUS_STRING_PATTERNS = [
    "ObRegisterCallbacks",
    "CmRegisterCallbackEx",
    "PsSetCreateProcessNotifyRoutine",
    "KeInsertQueueApc",
    "ZwTerminateProcess",
    "ActiveProcessLinks",
    "PsLoadedModuleList",
    "MmUnloadedDrivers",
    "PiDDBCacheTable",
    "MiRememberUnloadedDriver",
    "\\Registry\\Machine",
    "\\Device\\",
    "\\DosDevices\\",
    "DriverUnload",
    "taskmgr",
    "procexp",
    "processhacker",
    "sysmon",
    "wireshark",
    "x64dbg",
    "windbg",
    "ollydbg",
    "volatility",
    "mimikatz",
]

# Process names commonly targeted by anti-cheat / protection drivers
_TARGET_PROCESS_PATTERNS = [
    "csgo", "valorant", "apex", "fortnite",
    "chrome", "firefox", "explorer",
    "lsass", "csrss", "smss", "services",
    "cmd.exe", "powershell",
]


class ArchitectureReconstructor:
    """Generate a human-readable architecture summary from analysis results."""

    def summarize(
        self,
        file_info,
        depgraph,
        chains: list,
    ) -> dict:
        """Produce a complete architecture summary.

        Parameters
        ----------
        file_info : FileInfo or dict
            Must have: format, imports (dict), exports (list or via method),
            sections, entry_point, path.
        depgraph : object or None
            Dependency graph (optional).
        chains : list[Chain]
            Chain objects from ChainTracer (optional, can be empty).

        Returns
        -------
        dict with keys:
            type, summary, callbacks, protection_mechanisms, attack_chain,
            self_protection, strings_of_interest
        """
        imports = self._get_imports(file_info)
        exports = self._get_exports(file_info)
        file_format = self._get_attr(file_info, "format", "unknown")

        driver_type = self.classify_driver(imports)
        callbacks = self._identify_callbacks(imports, chains)
        self_protection = self.detect_self_protection(depgraph, file_info)
        attack_chain = self._extract_attack_chain(chains)
        protection_mechanisms = self._identify_protection_mechanisms(imports, chains)
        strings_of_interest = self._filter_suspicious_strings(file_info)

        summary = self._generate_summary(
            driver_type, callbacks, self_protection, attack_chain, file_format
        )

        return {
            "type": driver_type,
            "summary": summary,
            "callbacks": callbacks,
            "protection_mechanisms": protection_mechanisms,
            "attack_chain": attack_chain,
            "self_protection": self_protection,
            "strings_of_interest": strings_of_interest,
        }

    def classify_driver(self, imports: dict) -> str:
        """Classify driver type based on import patterns."""
        all_funcs = set()
        for dll, funcs in imports.items():
            if isinstance(funcs, list):
                all_funcs.update(funcs)
            elif isinstance(funcs, dict):
                all_funcs.update(funcs.values())

        has_ob_register = "ObRegisterCallbacks" in all_funcs
        has_cm_register = (
            "CmRegisterCallbackEx" in all_funcs or "CmRegisterCallback" in all_funcs
        )
        has_ps_notify = any(
            f.startswith("PsSetCreate") or f.startswith("PsSetLoad")
            for f in all_funcs
        )
        has_apc = "KeInsertQueueApc" in all_funcs or "KeInitializeApc" in all_funcs
        has_flt = "FltRegisterFilter" in all_funcs
        has_terminate = "ZwTerminateProcess" in all_funcs or "NtTerminateProcess" in all_funcs
        has_dkom_hints = any(
            f in all_funcs for f in ("MmGetSystemRoutineAddress",)
        )

        # Classification priority (most specific first)
        if has_ps_notify and has_apc:
            return "apc_injector"
        if has_flt:
            if has_ob_register or has_cm_register:
                return "protection_minifilter"
            return "minifilter"
        if has_ob_register and has_cm_register:
            return "process_registry_protection"
        if has_ob_register:
            if has_terminate:
                return "process_protection_and_termination"
            return "process_protection"
        if has_cm_register:
            return "registry_monitor"
        if has_ps_notify and has_terminate:
            return "process_monitor_with_kill"
        if has_ps_notify:
            return "process_monitor"
        if has_apc:
            return "apc_injector"
        if has_dkom_hints and not has_ob_register:
            return "rootkit_like"

        return "generic_driver"

    def detect_self_protection(self, depgraph, file_info) -> list[str]:
        """Identify self-protection mechanisms."""
        protections: list[str] = []
        exports = self._get_exports(file_info)
        imports = self._get_imports(file_info)
        all_funcs = set()
        for funcs in imports.values():
            if isinstance(funcs, list):
                all_funcs.update(funcs)

        # No DriverUnload = cannot be unloaded
        if "DriverUnload" not in exports:
            protections.append("No DriverUnload export — driver cannot be unloaded normally")

        # Registry protection via CmCallback
        if "CmRegisterCallbackEx" in all_funcs or "CmRegisterCallback" in all_funcs:
            protections.append(
                "Registry callback registered — may protect its own registry keys"
            )

        # ObRegisterCallbacks for handle protection
        if "ObRegisterCallbacks" in all_funcs:
            protections.append(
                "Object callbacks registered — can strip handle access rights"
            )

        # DKOM indicators
        if "MmGetSystemRoutineAddress" in all_funcs:
            protections.append(
                "Dynamic API resolution via MmGetSystemRoutineAddress — "
                "may resolve undocumented APIs for DKOM"
            )

        # Check for known DKOM-related strings
        strings_list = self._get_strings(file_info)
        dkom_indicators = {
            "PsLoadedModuleList": "PsLoadedModuleList access — may hide from driver list",
            "MmUnloadedDrivers": "MmUnloadedDrivers access — may clear unload traces",
            "PiDDBCacheTable": "PiDDBCacheTable access — may clean driver database cache",
            "ActiveProcessLinks": "ActiveProcessLinks reference — may perform process DKOM hiding",
            "MiRememberUnloadedDriver": "MiRememberUnloadedDriver — may patch unload tracking",
        }
        for s in strings_list:
            val = s if isinstance(s, str) else s.get("value", "")
            for indicator, desc in dkom_indicators.items():
                if indicator in val and desc not in protections:
                    protections.append(desc)

        # Check depgraph for writes to known offsets
        if depgraph is not None:
            nodes = {}
            if hasattr(depgraph, "nodes") and isinstance(depgraph.nodes, dict):
                nodes = depgraph.nodes
            elif isinstance(depgraph, dict) and "nodes" in depgraph:
                nodes = depgraph["nodes"]

            for nid, attrs in nodes.items():
                label = attrs.get("label", attrs.get("name", ""))
                # ActiveProcessLinks offset on Win10 x64 = 0x448
                if "0x448" in str(attrs) or "0x2f0" in str(attrs):
                    msg = "Writes to EPROCESS offset (potential DKOM)"
                    if msg not in protections:
                        protections.append(msg)

        return protections

    # ---------------------------------------------------------------
    # Internal helpers
    # ---------------------------------------------------------------

    @staticmethod
    def _get_attr(obj, attr: str, default=None):
        if isinstance(obj, dict):
            return obj.get(attr, default)
        return getattr(obj, attr, default)

    def _get_imports(self, file_info) -> dict:
        if isinstance(file_info, dict):
            return file_info.get("imports", {})
        return getattr(file_info, "imports", {})

    def _get_exports(self, file_info) -> list:
        if isinstance(file_info, dict):
            return file_info.get("exports", [])
        val = getattr(file_info, "exports", [])
        if callable(val):
            return val()
        return val

    def _get_strings(self, file_info) -> list:
        if isinstance(file_info, dict):
            return file_info.get("strings", [])
        val = getattr(file_info, "strings", [])
        if callable(val):
            return val()
        return val

    def _identify_callbacks(self, imports: dict, chains: list) -> list[dict]:
        """Identify registered callbacks and their behavior."""
        callbacks: list[dict] = []
        all_funcs = set()
        for funcs in imports.values():
            if isinstance(funcs, list):
                all_funcs.update(funcs)

        cb_apis = {
            "ObRegisterCallbacks": ("Object callback", "Filters handle operations on processes/threads"),
            "CmRegisterCallbackEx": ("Registry callback", "Monitors/blocks registry operations"),
            "CmRegisterCallback": ("Registry callback", "Monitors/blocks registry operations"),
            "PsSetCreateProcessNotifyRoutine": ("Process creation notify", "Notified on process creation/exit"),
            "PsSetCreateProcessNotifyRoutineEx": ("Process creation notify (Ex)", "Can block process creation"),
            "PsSetCreateProcessNotifyRoutineEx2": ("Process creation notify (Ex2)", "Extended process creation info"),
            "PsSetCreateThreadNotifyRoutine": ("Thread creation notify", "Notified on thread creation/exit"),
            "PsSetLoadImageNotifyRoutine": ("Image load notify", "Notified when images are loaded"),
            "FltRegisterFilter": ("Minifilter", "File system filter operations"),
        }

        for api, (cb_type, default_behavior) in cb_apis.items():
            if api in all_funcs:
                # Try to find more detail from chains
                behavior = default_behavior
                handler = "unknown"
                for chain in chains:
                    chain_steps = chain.steps if hasattr(chain, "steps") else []
                    for i, step in enumerate(chain_steps):
                        step_id = step.node_id if hasattr(step, "node_id") else ""
                        if api in step_id:
                            # Next step after registration is likely the handler
                            if i + 1 < len(chain_steps):
                                next_step = chain_steps[i + 1]
                                handler = next_step.node_id if hasattr(next_step, "node_id") else "unknown"
                            break

                callbacks.append({
                    "type": cb_type,
                    "api": api,
                    "handler": handler,
                    "behavior": behavior,
                })

        return callbacks

    def _extract_attack_chain(self, chains: list) -> list[str]:
        """Extract human-readable attack chain descriptions from Chain objects."""
        descriptions: list[str] = []
        seen: set[str] = set()

        for chain in chains:
            verdict = chain.verdict if hasattr(chain, "verdict") else ""
            if not verdict or verdict in seen:
                continue
            seen.add(verdict)

            steps = chain.steps if hasattr(chain, "steps") else []
            step_names = []
            for s in steps:
                nid = s.node_id if hasattr(s, "node_id") else str(s)
                step_names.append(nid)

            if step_names:
                desc = f"{' -> '.join(step_names)}: {verdict}"
            else:
                desc = verdict
            descriptions.append(desc)

        return descriptions

    def _identify_protection_mechanisms(self, imports: dict, chains: list) -> list[str]:
        """Identify protection mechanisms from imports and chains."""
        mechanisms: list[str] = []
        all_funcs = set()
        for funcs in imports.values():
            if isinstance(funcs, list):
                all_funcs.update(funcs)

        if "ObRegisterCallbacks" in all_funcs:
            mechanisms.append("Handle access filtering via ObRegisterCallbacks")
        if "CmRegisterCallbackEx" in all_funcs or "CmRegisterCallback" in all_funcs:
            mechanisms.append("Registry operation monitoring/blocking")
        if any(f.startswith("PsSetCreate") for f in all_funcs):
            mechanisms.append("Process/thread creation monitoring")
        if "PsSetLoadImageNotifyRoutine" in all_funcs:
            mechanisms.append("Image load monitoring")
        if "FltRegisterFilter" in all_funcs:
            mechanisms.append("File system filtering")
        if "ZwTerminateProcess" in all_funcs or "NtTerminateProcess" in all_funcs:
            mechanisms.append("Process termination capability")
        if "KeInsertQueueApc" in all_funcs:
            mechanisms.append("APC injection capability")
        if "ZwAllocateVirtualMemory" in all_funcs:
            mechanisms.append("Virtual memory allocation in target processes")

        return mechanisms

    def _filter_suspicious_strings(self, file_info) -> list[str]:
        """Filter strings of interest from file info."""
        raw_strings = self._get_strings(file_info)
        interesting: list[str] = []
        seen: set[str] = set()

        for s in raw_strings:
            val = s if isinstance(s, str) else s.get("value", "")
            if not val or val in seen:
                continue

            # Check against known suspicious patterns
            for pattern in _SUSPICIOUS_STRING_PATTERNS:
                if pattern.lower() in val.lower():
                    if val not in seen:
                        seen.add(val)
                        interesting.append(val)
                    break

            # Check for target process names
            for proc in _TARGET_PROCESS_PATTERNS:
                if proc.lower() in val.lower():
                    if val not in seen:
                        seen.add(val)
                        interesting.append(val)
                    break

        return interesting

    @staticmethod
    def _generate_summary(
        driver_type: str,
        callbacks: list[dict],
        self_protection: list[str],
        attack_chain: list[str],
        file_format: str,
    ) -> str:
        """Generate a 1-3 sentence summary."""
        parts: list[str] = []

        # Type description
        type_desc = {
            "process_protection": "process protection driver that uses ObRegisterCallbacks to filter handle operations",
            "process_registry_protection": "driver that protects both processes and registry keys via kernel callbacks",
            "registry_monitor": "registry monitoring driver using CmRegisterCallbackEx",
            "apc_injector": "driver that injects code into target processes via APC (Asynchronous Procedure Call)",
            "minifilter": "file system minifilter driver",
            "protection_minifilter": "combined protection driver with file system filtering and kernel callbacks",
            "process_monitor": "process monitoring driver that tracks process creation and termination",
            "process_monitor_with_kill": "process monitoring driver with process termination capability",
            "process_protection_and_termination": "process protection driver with termination capability",
            "rootkit_like": "driver with rootkit-like characteristics (dynamic API resolution, possible DKOM)",
            "generic_driver": "kernel-mode driver",
        }
        desc = type_desc.get(driver_type, f"{driver_type} driver")

        is_driver = "DRIVER" in file_format.upper()
        prefix = "Kernel" if is_driver else "User-mode"
        parts.append(f"{prefix} {desc}.")

        # Callback summary
        if callbacks:
            cb_types = [cb["type"] for cb in callbacks]
            parts.append(f"Registers {len(callbacks)} callback(s): {', '.join(cb_types)}.")

        # Self-protection
        if self_protection:
            parts.append(
                f"Self-protection: {'; '.join(self_protection[:2])}."
            )

        return " ".join(parts)
