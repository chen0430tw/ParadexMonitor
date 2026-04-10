"""
Build a DepGraph from a CallGraph and PEAdapter.

Combines structural information (call graph), import resolution,
string references, and callback registration detection into a
unified queryable dependency graph.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from ppm_engine.depgraph.nodes import Node
from ppm_engine.depgraph.edges import Edge
from ppm_engine.depgraph.query import DepGraph

if TYPE_CHECKING:
    from ppm_engine.topology.callgraph import CallGraph
    from ppm_engine.adapters.pe import PEAdapter


# Kernel callback registration APIs and their handler argument positions
# (api_name_substring, handler_arg_description)
_CALLBACK_APIS = {
    "ObRegisterCallbacks": "OB_CALLBACK_REGISTRATION structure",
    "CmRegisterCallbackEx": "callback routine (arg 0)",
    "CmRegisterCallback": "callback routine (arg 0)",
    "PsSetCreateProcessNotifyRoutine": "notify routine (arg 0)",
    "PsSetCreateProcessNotifyRoutineEx": "notify routine (arg 0)",
    "PsSetCreateProcessNotifyRoutineEx2": "notify routine (arg 1)",
    "PsSetCreateThreadNotifyRoutine": "notify routine (arg 0)",
    "PsSetLoadImageNotifyRoutine": "notify routine (arg 0)",
    "PsSetLoadImageNotifyRoutineEx": "notify routine (arg 1)",
    "IoRegisterShutdownNotification": "device object (arg 0)",
    "FltRegisterFilter": "FLT_REGISTRATION structure",
    "ExRegisterCallback": "callback routine (arg 1)",
}


class DepGraphBuilder:
    """Build a DepGraph from a CallGraph + PEAdapter."""

    def build(self, callgraph: CallGraph, adapter: PEAdapter) -> DepGraph:
        """Construct the full dependency graph.

        Steps:
            1. Create FunctionNodes from callgraph
            2. Create ImportNodes from adapter.imports()
            3. Create StringNodes from adapter.strings()
            4. Create Calls edges from callgraph
            5. Detect callback registrations
            6. Return DepGraph
        """
        graph = DepGraph()

        # --- Step 1: Function nodes ---
        for addr, fn in callgraph.functions.items():
            if fn.is_import:
                continue  # handled in step 2
            node_id = f"func_{addr:#x}"
            graph.add_node(Node(
                id=node_id,
                address=addr,
                label=fn.name or f"sub_{addr:X}",
                node_type="function",
                metadata={
                    "size": fn.size,
                    "num_calls": len(fn.calls),
                    "num_callers": len(fn.called_by),
                },
            ))

        # --- Step 2: Import nodes ---
        import_id_map: dict[int, str] = {}  # addr -> node_id
        imports = adapter.imports()
        for dll, funcs in imports.items():
            for func_name in funcs:
                # Find the address from callgraph if available
                addr = self._find_import_addr(callgraph, dll, func_name)
                node_id = f"import_{func_name}"
                # Handle duplicate import names from different DLLs
                if node_id in graph.nodes:
                    node_id = f"import_{dll}!{func_name}"
                graph.add_node(Node(
                    id=node_id,
                    address=addr,
                    label=func_name,
                    node_type="import",
                    metadata={"dll": dll},
                ))
                if addr != 0:
                    import_id_map[addr] = node_id

        # --- Step 3: String nodes ---
        strings = adapter.strings(min_len=8)
        for idx, s in enumerate(strings):
            value = s["value"]
            # Skip very long strings or binary-looking content
            if len(value) > 256:
                value = value[:256] + "..."
            node_id = f"string_{idx}_{s['rva']:#x}"
            graph.add_node(Node(
                id=node_id,
                address=s["rva"],
                label=value,
                node_type="string",
                metadata={"encoding": s["encoding"], "rva": s["rva"]},
            ))

        # --- Step 4: Call edges ---
        for addr, fn in callgraph.functions.items():
            if fn.is_import:
                continue
            src_id = f"func_{addr:#x}"
            for callee_addr in fn.calls:
                callee_fn = callgraph.functions.get(callee_addr)
                if callee_fn is None:
                    continue
                if callee_fn.is_import:
                    # Link to import node
                    dst_id = import_id_map.get(callee_addr)
                    if dst_id is None:
                        dst_id = f"import_{callee_fn.import_name}"
                        if dst_id not in graph.nodes:
                            dst_id = f"import_{callee_fn.import_dll}!{callee_fn.import_name}"
                else:
                    dst_id = f"func_{callee_addr:#x}"

                if dst_id in graph.nodes:
                    graph.add_edge(Edge(
                        src=src_id,
                        dst=dst_id,
                        edge_type="calls",
                    ))

        # --- Step 5: Detect callback registrations ---
        self._detect_callbacks(graph, callgraph, import_id_map)

        return graph

    def _find_import_addr(
        self, callgraph: CallGraph, dll: str, func_name: str
    ) -> int:
        """Find the address of an import in the call graph."""
        for addr, fn in callgraph.functions.items():
            if fn.is_import and fn.import_name == func_name:
                if not dll or fn.import_dll.lower() == dll.lower():
                    return addr
        return 0

    def _detect_callbacks(
        self,
        graph: DepGraph,
        callgraph: CallGraph,
        import_id_map: dict[int, str],
    ) -> None:
        """Detect callback registration patterns and create 'registers' edges.

        For each known callback API, find callers and create:
          - A callback node representing the handler
          - A 'registers' edge from the registrar function to the callback node
        """
        callback_counter = 0

        for addr, fn in callgraph.functions.items():
            if fn.is_import:
                continue

            src_id = f"func_{addr:#x}"

            for callee_addr in fn.calls:
                callee_fn = callgraph.functions.get(callee_addr)
                if callee_fn is None or not callee_fn.is_import:
                    continue

                # Check if this import is a callback registration API
                api_name = callee_fn.import_name
                matched_api = None
                for api_pattern in _CALLBACK_APIS:
                    if api_pattern.lower() in api_name.lower():
                        matched_api = api_pattern
                        break

                if matched_api is None:
                    continue

                # Create a callback node
                callback_counter += 1
                cb_id = f"callback_{callback_counter}_{addr:#x}"
                handler_desc = _CALLBACK_APIS[matched_api]

                graph.add_node(Node(
                    id=cb_id,
                    address=addr,
                    label=f"Handler@{addr:#x} ({matched_api})",
                    node_type="callback",
                    metadata={
                        "registered_by": fn.name,
                        "api": matched_api,
                        "handler_arg": handler_desc,
                    },
                ))

                # Edge: registrar function -> callback handler
                graph.add_edge(Edge(
                    src=src_id,
                    dst=cb_id,
                    edge_type="registers",
                    metadata={"callback_api": matched_api},
                ))

                # Also link the callback registration call itself
                import_node_id = import_id_map.get(callee_addr)
                if import_node_id and import_node_id in graph.nodes:
                    graph.add_edge(Edge(
                        src=cb_id,
                        dst=import_node_id,
                        edge_type="references",
                        metadata={"relationship": "registered_via"},
                    ))
