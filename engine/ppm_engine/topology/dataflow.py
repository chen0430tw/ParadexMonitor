"""
Data flow analysis — track argument values passed to API calls.

This module provides a stub interface for future implementation of
inter-procedural data flow tracking.  The interface is stable; the
implementation will be filled in when the engine gains SSA/VEX-IR
support (e.g., via angr or miasm).
"""
from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ppm_engine.topology.callgraph import CallGraph


def track_arguments(graph: CallGraph, target_addr: int) -> dict[int, dict[str, str]]:
    """Track what values are passed to a specific API call.

    Analyses callers of *target_addr* and attempts to determine the
    concrete or symbolic values of each argument at each call site.

    Parameters:
        graph: The call graph containing disassembly information.
        target_addr: Address of the target function/import to analyse.

    Returns:
        Mapping of ``{arg_index: {"source": ..., "value": ...}}``.

        For example, for ``ObOpenObjectByPointer``::

            {
                0: {"source": "register", "value": "rcx (from caller arg0)"},
                1: {"source": "immediate", "value": "0x200"},
            }

        Currently returns an empty dict.  Full implementation requires
        SSA-based register/stack tracking which is planned for v0.3.

    TODO:
        - Build per-function SSA form from capstone disassembly
        - Track register definitions backward from call sites
        - Handle stack-passed arguments (x64 shadow space + spill)
        - Resolve lea-based string/global references
    """
    # Verify the target exists in the graph
    if target_addr not in graph.functions:
        return {}

    # Future: iterate over callers, disassemble backward from each
    # call site, and track register assignments (rcx, rdx, r8, r9
    # for x64 calling convention).
    return {}
