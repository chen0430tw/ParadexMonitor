"""
Queryable dependency graph — the core analysis interface.

Provides BFS traversal, path finding, impact analysis, and
multiple export formats (JSON, DOT, ASCII tree).
"""
from __future__ import annotations

import json
from collections import deque
from typing import Optional

from ppm_engine.depgraph.nodes import Node
from ppm_engine.depgraph.edges import Edge


_TYPE_ALIASES: dict[str, list[str]] = {
    "obcallback": ["ObRegisterCallbacks"],
    "cmcallback": ["CmRegisterCallbackEx", "CmRegisterCallback"],
    "processnotify": ["PsSetCreateProcessNotifyRoutine", "PsSetCreateProcessNotifyRoutineEx",
                       "PsSetCreateProcessNotifyRoutineEx2"],
    "threadnotify": ["PsSetCreateThreadNotifyRoutine"],
    "imagenotify": ["PsSetLoadImageNotifyRoutine", "PsSetLoadImageNotifyRoutineEx"],
    "minifilter": ["FltRegisterFilter"],
    "notify": ["PsSetCreateProcessNotifyRoutine", "PsSetCreateThreadNotifyRoutine",
                "PsSetLoadImageNotifyRoutine"],
}


class DepGraph:
    """A directed dependency graph with rich query capabilities."""

    def __init__(self) -> None:
        self.nodes: dict[str, Node] = {}
        self.edges: list[Edge] = []
        # Adjacency caches (rebuilt lazily)
        self._outgoing: dict[str, list[Edge]] | None = None
        self._incoming: dict[str, list[Edge]] | None = None

    # ------------------------------------------------------------------
    # Mutation
    # ------------------------------------------------------------------
    def add_node(self, node: Node) -> None:
        """Add a node to the graph (replaces if same id exists)."""
        self.nodes[node.id] = node
        self._invalidate_cache()

    def add_edge(self, edge: Edge) -> None:
        """Add a directed edge to the graph."""
        self.edges.append(edge)
        self._invalidate_cache()

    def _invalidate_cache(self) -> None:
        self._outgoing = None
        self._incoming = None

    def _build_adjacency(self) -> None:
        """Build outgoing and incoming adjacency lists from edge list."""
        out: dict[str, list[Edge]] = {}
        inc: dict[str, list[Edge]] = {}
        for e in self.edges:
            out.setdefault(e.src, []).append(e)
            inc.setdefault(e.dst, []).append(e)
        self._outgoing = out
        self._incoming = inc

    @property
    def outgoing(self) -> dict[str, list[Edge]]:
        if self._outgoing is None:
            self._build_adjacency()
        return self._outgoing  # type: ignore[return-value]

    @property
    def incoming(self) -> dict[str, list[Edge]]:
        if self._incoming is None:
            self._build_adjacency()
        return self._incoming  # type: ignore[return-value]

    # ------------------------------------------------------------------
    # Node resolution
    # ------------------------------------------------------------------
    def _resolve_node_id(self, query: str) -> Optional[str]:
        """Fuzzy-resolve a user query to a node ID.

        Accepts: "sub_1120", "0x1120", "1120", "func_0x1120",
                 "MmMapIoSpace", "import_MmMapIoSpace", etc.
        """
        if query in self.nodes:
            return query
        q = query.strip().lower()

        # Try "func_0x" + hex prefix
        if q.startswith("sub_"):
            candidate = f"func_0x{q[4:]}"
            if candidate in self.nodes:
                return candidate
        # Try bare hex: "1120" -> "func_0x1120"
        try:
            int(q, 16)
            candidate = f"func_0x{q}"
            if candidate in self.nodes:
                return candidate
        except ValueError:
            pass
        # Try "0x1120" -> "func_0x1120"
        if q.startswith("0x"):
            candidate = f"func_{q}"
            if candidate in self.nodes:
                return candidate
        # Try import prefix
        candidate = f"import_{query}"
        if candidate in self.nodes:
            return candidate
        # Substring match on label
        for nid, node in self.nodes.items():
            label = getattr(node, "label", "")
            if q == label.lower() or query == label:
                return nid
        return None

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------
    def who_registers(self, callback_type: str) -> list[dict]:
        """Find all 'registers' edges where dst matches *callback_type* pattern.

        Parameters:
            callback_type: Substring to match against destination node labels,
                           IDs, edge metadata, or node metadata['api'].
                           Also supports short aliases: ``"ObCallback"`` matches
                           ``ObRegisterCallbacks``, ``"CmCallback"`` matches
                           ``CmRegisterCallback*``, etc.

        Returns:
            List of dicts: ``[{"registrar": ..., "handler": ..., "type": ...}]``
        """
        # Expand type aliases: "ObCallback" -> ["ObRegisterCallbacks"]
        query_lower = callback_type.lower()
        expanded_apis = _TYPE_ALIASES.get(query_lower, [])

        results: list[dict] = []
        for edge in self.edges:
            if edge.edge_type != "registers":
                continue
            dst_node = self.nodes.get(edge.dst)
            src_node = self.nodes.get(edge.src)
            if dst_node is None or src_node is None:
                continue

            cb_api = edge.metadata.get("callback_api", "")
            node_api = dst_node.metadata.get("api", "")

            # Check alias match first (exact API name match)
            if expanded_apis:
                if cb_api in expanded_apis or node_api in expanded_apis:
                    results.append({
                        "registrar": src_node.label,
                        "registrar_id": src_node.id,
                        "handler": dst_node.label,
                        "handler_id": dst_node.id,
                        "type": cb_api or node_api or "unknown",
                    })
                    continue

            # Substring match against label, id, edge metadata, and node metadata
            target_str = f"{dst_node.label} {dst_node.id} {cb_api} {node_api}"
            if query_lower in target_str.lower():
                results.append({
                    "registrar": src_node.label,
                    "registrar_id": src_node.id,
                    "handler": dst_node.label,
                    "handler_id": dst_node.id,
                    "type": cb_api or node_api or "unknown",
                })
        return results

    def what_calls(self, func_id: str) -> list[Node]:
        """All nodes that have a 'calls' edge to *func_id*."""
        callers: list[Node] = []
        for edge in self.incoming.get(func_id, []):
            if edge.edge_type == "calls":
                node = self.nodes.get(edge.src)
                if node is not None:
                    callers.append(node)
        return callers

    def trace_from(self, node_id: str, depth: int = 10) -> dict:
        """BFS from *node_id*, return tree structure up to *depth*.

        Returns a nested dict::

            {
                "id": "func_0x1000",
                "label": "DriverEntry",
                "children": [
                    {"id": "import_Ob...", "label": "ObRegisterCallbacks", "children": [...]},
                    ...
                ]
            }
        """
        resolved = self._resolve_node_id(node_id)
        if not resolved:
            return {}
        node_id = resolved

        def _build(nid: str, d: int, visited: set[str]) -> dict:
            node = self.nodes[nid]
            result: dict = {"id": nid, "label": node.label, "type": node.node_type}
            if d <= 0 or nid in visited:
                return result
            visited = visited | {nid}  # copy to allow branching
            children: list[dict] = []
            for edge in self.outgoing.get(nid, []):
                if edge.dst in self.nodes:
                    child = _build(edge.dst, d - 1, visited)
                    child["edge_type"] = edge.edge_type
                    children.append(child)
            if children:
                result["children"] = children
            return result

        return _build(node_id, depth, set())

    def find_path(self, src_id: str, dst_id: str) -> list[str] | None:
        """Shortest path between two nodes (BFS on outgoing edges).

        Returns list of node IDs forming the path, or None if no path exists.
        """
        if src_id not in self.nodes or dst_id not in self.nodes:
            return None
        if src_id == dst_id:
            return [src_id]

        visited: set[str] = {src_id}
        queue: deque[list[str]] = deque([[src_id]])
        while queue:
            path = queue.popleft()
            current = path[-1]
            for edge in self.outgoing.get(current, []):
                nxt = edge.dst
                if nxt == dst_id:
                    return path + [nxt]
                if nxt not in visited:
                    visited.add(nxt)
                    queue.append(path + [nxt])
        return None

    def find_sinks(self, api_name: str) -> list[list[str]]:
        """Find all call chains that end at an import matching *api_name*.

        Searches backward from matching import nodes to find all paths
        from root functions to the target import.

        Returns:
            List of paths, each path is a list of node IDs from caller to import.
        """
        # Find all import nodes matching api_name
        targets: list[str] = []
        for nid, node in self.nodes.items():
            if node.node_type == "import" and api_name.lower() in node.label.lower():
                targets.append(nid)

        if not targets:
            return []

        # For each root, try to find path to each target
        root_ids = [
            nid for nid, node in self.nodes.items()
            if node.node_type == "function" and not self.incoming.get(nid)
        ]

        all_paths: list[list[str]] = []
        for target in targets:
            for root in root_ids:
                p = self.find_path(root, target)
                if p:
                    all_paths.append(p)

            # Also check non-root callers for shorter chains
            for edge in self.incoming.get(target, []):
                if edge.edge_type == "calls" and edge.src not in root_ids:
                    all_paths.append([edge.src, target])

        return all_paths

    def who_calls(self, node_id: str, depth: int = 10) -> list[list[str]]:
        """Find all callers of a node (reverse BFS).

        Returns a list of call chains leading TO this node, each chain
        ordered from root caller to the target node.
        """
        # Fuzzy match: allow "sub_1120", "0x1120", "1120", "func_0x1120"
        if node_id not in self.nodes:
            resolved = self._resolve_node_id(node_id)
            if resolved:
                node_id = resolved
            else:
                return []

        chains: list[list[str]] = []
        # BFS backwards through incoming edges
        queue: deque[list[str]] = deque([[node_id]])
        visited: set[str] = {node_id}
        while queue:
            path = queue.popleft()
            cur = path[0]  # head of chain (we're prepending)
            has_caller = False
            for edge in self.incoming.get(cur, []):
                if edge.src not in visited and len(path) < depth:
                    has_caller = True
                    visited.add(edge.src)
                    new_path = [edge.src] + path
                    queue.append(new_path)
                    # If this caller has no incoming edges, it's a root
                    if not self.incoming.get(edge.src):
                        chains.append(new_path)
            if not has_caller and len(path) > 1:
                chains.append(path)

        return chains

    def impact_of(self, node_id: str) -> dict:
        """If this node is removed/patched, what is affected?

        Returns all nodes reachable FROM this node via outgoing edges,
        grouped by node type.
        """
        resolved = self._resolve_node_id(node_id)
        if not resolved:
            return {"affected": [], "by_type": {}}
        node_id = resolved

        visited: set[str] = set()
        queue = deque([node_id])
        while queue:
            cur = queue.popleft()
            if cur in visited:
                continue
            visited.add(cur)
            for edge in self.outgoing.get(cur, []):
                if edge.dst not in visited:
                    queue.append(edge.dst)

        # Remove the source node itself
        visited.discard(node_id)

        by_type: dict[str, list[str]] = {}
        for nid in visited:
            node = self.nodes.get(nid)
            if node:
                by_type.setdefault(node.node_type, []).append(nid)

        return {
            "source": node_id,
            "affected_count": len(visited),
            "affected": sorted(visited),
            "by_type": by_type,
        }

    # ------------------------------------------------------------------
    # Export
    # ------------------------------------------------------------------
    def to_json(self) -> dict:
        """Full graph as JSON-serializable dict (nodes + edges)."""
        return {
            "nodes": {nid: n.to_dict() for nid, n in self.nodes.items()},
            "edges": [e.to_dict() for e in self.edges],
            "stats": {
                "node_count": len(self.nodes),
                "edge_count": len(self.edges),
                "node_types": _count_by(self.nodes.values(), lambda n: n.node_type),
                "edge_types": _count_by(self.edges, lambda e: e.edge_type),
            },
        }

    def to_dot(self) -> str:
        """Graphviz DOT format with color-coded node types."""
        from ppm_engine.depgraph.render import to_dot
        return to_dot(self)

    def to_ascii(self) -> str:
        """Simple ASCII tree from entry points."""
        from ppm_engine.depgraph.render import to_ascii_tree
        # Find roots (nodes with no incoming edges)
        roots = [
            nid for nid in self.nodes
            if not self.incoming.get(nid)
        ]
        if not roots:
            # Fallback: use first function node
            for nid, node in self.nodes.items():
                if node.node_type == "function":
                    roots = [nid]
                    break
        if not roots:
            return "(empty graph)"

        parts: list[str] = []
        for root_id in sorted(roots):
            parts.append(to_ascii_tree(self, root_id))
        return "\n".join(parts)


def _count_by(items, key_fn) -> dict[str, int]:
    counts: dict[str, int] = {}
    for item in items:
        k = key_fn(item)
        counts[k] = counts.get(k, 0) + 1
    return counts
