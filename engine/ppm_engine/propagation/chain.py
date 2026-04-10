"""
Trace execution chains from entry points through callbacks to API sinks.

Given a dependency graph (nodes = functions/addresses, edges = calls/data-flow),
this module discovers interesting paths such as:

    DriverEntry -> ObRegisterCallbacks -> PreOp handler -> PsGetProcessId -> ...

The output is a list of Chain objects describing each path with a verdict.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from collections import deque
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    pass  # DepGraph imported at runtime to avoid circular deps


# ---------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------

@dataclass
class ChainStep:
    node_id: str
    action: str       # "calls", "registers", "passes_arg"
    detail: str = ""  # e.g. "DesiredAccess=0x200"


@dataclass
class Chain:
    steps: list[ChainStep] = field(default_factory=list)
    verdict: str = ""  # e.g. "No ALL_ACCESS handle creation"

    def to_dict(self) -> dict:
        return {
            "steps": [
                {"node": s.node_id, "action": s.action, "detail": s.detail}
                for s in self.steps
            ],
            "verdict": self.verdict,
        }

    def __repr__(self) -> str:
        path = " -> ".join(s.node_id for s in self.steps)
        return f"Chain({path} | {self.verdict})"


# ---------------------------------------------------------------
# Well-known sets
# ---------------------------------------------------------------

CALLBACK_REGISTRATION_APIS = {
    "ObRegisterCallbacks",
    "CmRegisterCallbackEx",
    "CmRegisterCallback",
    "PsSetCreateProcessNotifyRoutine",
    "PsSetCreateProcessNotifyRoutineEx",
    "PsSetCreateProcessNotifyRoutineEx2",
    "PsSetCreateThreadNotifyRoutine",
    "PsSetLoadImageNotifyRoutine",
    "FltRegisterFilter",
}

DANGEROUS_SINK_APIS = {
    "ObOpenObjectByPointer",
    "ZwTerminateProcess",
    "NtTerminateProcess",
    "KeInsertQueueApc",
    "KeInitializeApc",
    "ZwOpenProcess",
    "NtOpenProcess",
    "ZwAllocateVirtualMemory",
    "ZwWriteVirtualMemory",
    "MmCopyVirtualMemory",
    "ZwSetInformationProcess",
    "ZwSetInformationThread",
    "MmGetSystemRoutineAddress",
}

ENTRY_POINT_NAMES = {
    "DriverEntry",
    "GsDriverEntry",
    "DllMain",
    "EntryPoint",
    "entry_point",
}


# ---------------------------------------------------------------
# ChainTracer
# ---------------------------------------------------------------

class ChainTracer:
    """Trace chains through a DepGraph.

    The graph is expected to be a dict-of-dicts adjacency structure:
        graph.nodes  : dict[str, dict]   — node_id -> attributes
        graph.edges  : dict[str, list[dict]] — source_id -> [{target, action, detail}, ...]

    If the graph is None or has no nodes, methods return empty lists.
    """

    def __init__(self, depgraph):
        self.graph = depgraph

    # ----------------------------------------------------------
    # helpers
    # ----------------------------------------------------------

    def _get_nodes(self) -> dict:
        """Return node dict: id -> {label, node_type, address, ...}."""
        if self.graph is None:
            return {}
        raw = None
        if hasattr(self.graph, "nodes"):
            raw = self.graph.nodes
        elif isinstance(self.graph, dict) and "nodes" in self.graph:
            raw = self.graph["nodes"]
        if raw is None:
            return {}
        if not isinstance(raw, dict):
            return {}
        # Adapt: if values are dataclass/objects with .label, convert to dicts
        result = {}
        for k, v in raw.items():
            if isinstance(v, dict):
                result[k] = v
            elif hasattr(v, "__dataclass_fields__"):
                from dataclasses import asdict
                result[k] = asdict(v)
            elif hasattr(v, "label"):
                result[k] = {"label": v.label, "node_type": getattr(v, "node_type", ""),
                             "address": getattr(v, "address", 0)}
            else:
                result[k] = {"label": str(v)}
        return result

    def _get_edges(self) -> dict:
        """Return edge adjacency: source_id -> [{target, action, detail}, ...]."""
        if self.graph is None:
            return {}
        raw = None
        if hasattr(self.graph, "edges"):
            raw = self.graph.edges
        elif isinstance(self.graph, dict) and "edges" in self.graph:
            raw = self.graph["edges"]
        if raw is None:
            return {}
        # If already adjacency dict, return as-is
        if isinstance(raw, dict):
            return raw
        # If list of Edge dataclasses or dicts, build adjacency
        adj: dict[str, list[dict]] = {}
        for e in raw:
            if isinstance(e, dict):
                src = e.get("src", "")
                entry = {"target": e.get("dst", ""), "action": e.get("edge_type", "calls"),
                         "detail": e.get("detail", "")}
            elif hasattr(e, "src"):
                src = e.src
                entry = {"target": e.dst, "action": getattr(e, "edge_type", "calls"),
                         "detail": getattr(e, "metadata", {}).get("detail", "") if isinstance(getattr(e, "metadata", None), dict) else ""}
            else:
                continue
            adj.setdefault(src, []).append(entry)
        return adj

    def _successors(self, node_id: str) -> list[dict]:
        """Return outgoing edges from *node_id*."""
        edges = self._get_edges()
        return edges.get(node_id, [])

    def _predecessors(self, node_id: str) -> list[tuple[str, dict]]:
        """Return (source_id, edge_dict) pairs for all edges pointing to *node_id*."""
        result: list[tuple[str, dict]] = []
        for src, edge_list in self._get_edges().items():
            for e in edge_list:
                target = e.get("target", e.get("to", ""))
                if target == node_id:
                    result.append((src, e))
        return result

    def _all_node_ids(self) -> list[str]:
        return list(self._get_nodes().keys())

    def _node_attr(self, node_id: str) -> dict:
        return self._get_nodes().get(node_id, {})

    def _is_interesting_target(self, name: str) -> bool:
        return name in CALLBACK_REGISTRATION_APIS or name in DANGEROUS_SINK_APIS

    def _find_entry_points(self) -> list[str]:
        """Auto-discover entry points (nodes with entry-point-like names or no predecessors)."""
        nodes = self._get_nodes()
        entries: list[str] = []
        for nid, attrs in nodes.items():
            label = attrs.get("label", attrs.get("name", nid))
            if label in ENTRY_POINT_NAMES or attrs.get("is_entry", False):
                entries.append(nid)
        # Also include nodes with zero in-degree
        if not entries:
            has_incoming = set()
            for edge_list in self._get_edges().values():
                for e in edge_list:
                    has_incoming.add(e.get("target", e.get("to", "")))
            for nid in nodes:
                if nid not in has_incoming:
                    entries.append(nid)
        return entries

    def _classify_verdict(self, chain: Chain) -> str:
        """Assign a verdict based on the APIs encountered in the chain."""
        apis_seen = set()
        for step in chain.steps:
            apis_seen.add(step.node_id)

        if apis_seen & {"ZwTerminateProcess", "NtTerminateProcess"}:
            return "Process termination capability"
        if apis_seen & {"KeInsertQueueApc", "KeInitializeApc"}:
            return "APC injection capability"
        if apis_seen & {"ObOpenObjectByPointer"}:
            return "Object handle manipulation"
        if apis_seen & {"ZwAllocateVirtualMemory", "ZwWriteVirtualMemory", "MmCopyVirtualMemory"}:
            return "Remote memory manipulation"
        if apis_seen & CALLBACK_REGISTRATION_APIS:
            if apis_seen & {"ObRegisterCallbacks"}:
                return "Object callback registration — handle access filtering"
            if apis_seen & {"CmRegisterCallbackEx", "CmRegisterCallback"}:
                return "Registry callback registration — registry monitoring/protection"
            return "Kernel callback registration"
        return "Interesting API chain"

    # ----------------------------------------------------------
    # public API
    # ----------------------------------------------------------

    def trace_from_entry(self, entry_id: str, max_depth: int = 15) -> list[Chain]:
        """DFS from *entry_id*, record all paths that reach callback registrations
        or dangerous API sinks.

        Returns one Chain per interesting path found.
        """
        results: list[Chain] = []
        visited: set[str] = set()

        def _dfs(node_id: str, path: list[ChainStep], depth: int):
            if depth > max_depth:
                return
            if node_id in visited:
                return
            visited.add(node_id)

            for edge in self._successors(node_id):
                target = edge.get("target", edge.get("to", ""))
                action = edge.get("action", edge.get("type", "calls"))
                detail = edge.get("detail", "")

                step = ChainStep(node_id=target, action=action, detail=detail)
                new_path = path + [step]

                # Check if we reached something interesting
                target_label = self._node_attr(target).get("label",
                               self._node_attr(target).get("name", target))
                if self._is_interesting_target(target_label) or self._is_interesting_target(target):
                    chain = Chain(
                        steps=[ChainStep(node_id=entry_id, action="entry")] + new_path
                    )
                    chain.verdict = self._classify_verdict(chain)
                    results.append(chain)

                # Continue DFS
                _dfs(target, new_path, depth + 1)

            visited.discard(node_id)

        _dfs(entry_id, [], 0)
        return results

    def trace_to_sink(self, sink_api: str) -> list[Chain]:
        """Find all paths from any entry point that reach the given API.

        Reverse BFS from sink, then format as forward chains.
        """
        nodes = self._get_nodes()

        # Find all nodes matching sink_api
        sink_nodes: list[str] = []
        for nid, attrs in nodes.items():
            label = attrs.get("label", attrs.get("name", nid))
            if label == sink_api or nid == sink_api:
                sink_nodes.append(nid)

        if not sink_nodes:
            return []

        entries = set(self._find_entry_points())
        results: list[Chain] = []

        for sink_id in sink_nodes:
            # Reverse BFS to find paths back to entry points
            queue: deque[list[str]] = deque([[sink_id]])
            seen: set[str] = {sink_id}

            while queue:
                path = queue.popleft()
                current = path[-1]

                if current in entries:
                    # Build forward chain (reverse the path)
                    forward = list(reversed(path))
                    steps = []
                    for i, nid in enumerate(forward):
                        action = "entry" if i == 0 else "calls"
                        steps.append(ChainStep(node_id=nid, action=action))
                    chain = Chain(steps=steps)
                    chain.verdict = self._classify_verdict(chain)
                    results.append(chain)
                    continue

                if len(path) > 15:
                    continue

                for src, edge in self._predecessors(current):
                    if src not in seen:
                        seen.add(src)
                        queue.append(path + [src])

        return results

    def trace_callback_chain(self, register_api: str) -> list[Chain]:
        """Find: who calls register_api -> what handler is registered ->
        what does handler call -> full chain.

        e.g. for ObRegisterCallbacks:
            DriverEntry -> ObRegisterCallbacks -> registers PreOp
            -> PreOp calls PsGetProcessId -> ...
        """
        nodes = self._get_nodes()
        results: list[Chain] = []

        # Find nodes representing the registration API
        reg_nodes: list[str] = []
        for nid, attrs in nodes.items():
            label = attrs.get("label", attrs.get("name", nid))
            if label == register_api or nid == register_api:
                reg_nodes.append(nid)

        for reg_node in reg_nodes:
            # Find callers (who calls the registration)
            callers = self._predecessors(reg_node)

            # Find handlers registered by this call
            # Look for edges from the registration node with action "registers"
            handler_edges = [
                e for e in self._successors(reg_node)
                if e.get("action", e.get("type", "")) in ("registers", "passes_arg", "callback")
            ]

            # Also check if any edges from callers have "registers" semantic
            if not handler_edges:
                for caller_id, _ in callers:
                    for e in self._successors(caller_id):
                        if e.get("action", e.get("type", "")) in ("registers", "callback"):
                            handler_edges.append(e)

            for caller_id, caller_edge in callers:
                for handler_edge in handler_edges:
                    handler_id = handler_edge.get("target", handler_edge.get("to", ""))
                    if not handler_id:
                        continue

                    # Build chain: caller -> register_api -> handler -> handler's callees
                    steps = [
                        ChainStep(node_id=caller_id, action="entry"),
                        ChainStep(node_id=reg_node, action="calls",
                                  detail=f"registers callback via {register_api}"),
                        ChainStep(node_id=handler_id, action="registers",
                                  detail="callback handler"),
                    ]

                    # Trace what the handler calls (one level deep)
                    for callee_edge in self._successors(handler_id):
                        callee = callee_edge.get("target", callee_edge.get("to", ""))
                        detail = callee_edge.get("detail", "")
                        steps.append(ChainStep(node_id=callee, action="calls", detail=detail))

                    chain = Chain(steps=steps)
                    chain.verdict = self._classify_verdict(chain)
                    results.append(chain)

        return results

    def all_interesting_chains(self) -> list[Chain]:
        """Auto-discover all chains involving callback registration or dangerous APIs."""
        results: list[Chain] = []
        entries = self._find_entry_points()

        # Trace forward from every entry point
        for entry in entries:
            results.extend(self.trace_from_entry(entry))

        # Trace backward from dangerous sinks
        for sink in DANGEROUS_SINK_APIS:
            results.extend(self.trace_to_sink(sink))

        # Trace callback registration chains
        for reg_api in CALLBACK_REGISTRATION_APIS:
            results.extend(self.trace_callback_chain(reg_api))

        # Deduplicate chains with identical step sequences
        seen_keys: set[str] = set()
        unique: list[Chain] = []
        for chain in results:
            key = "|".join(f"{s.node_id}:{s.action}" for s in chain.steps)
            if key not in seen_keys:
                seen_keys.add(key)
                unique.append(chain)

        return unique
