"""
Compare two DepGraphs to identify structural changes.

Useful for diffing two versions of the same driver to detect
added/removed functions, imports, callback registrations, etc.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ppm_engine.depgraph.query import DepGraph


def diff_graphs(a: DepGraph, b: DepGraph) -> dict:
    """Compare two DepGraphs and return a structured diff.

    Parameters:
        a: The "before" graph (e.g., older version of the driver).
        b: The "after" graph (e.g., newer version of the driver).

    Returns:
        A dict with keys:
            - ``added_nodes``: nodes in *b* but not in *a*
            - ``removed_nodes``: nodes in *a* but not in *b*
            - ``added_edges``: edges in *b* but not in *a*
            - ``removed_edges``: edges in *a* but not in *b*
            - ``modified_nodes``: nodes present in both but with changed metadata
            - ``summary``: human-readable summary string
    """
    # --- Node diff ---
    a_ids = set(a.nodes.keys())
    b_ids = set(b.nodes.keys())

    added_node_ids = b_ids - a_ids
    removed_node_ids = a_ids - b_ids
    common_node_ids = a_ids & b_ids

    added_nodes = [b.nodes[nid].to_dict() for nid in sorted(added_node_ids)]
    removed_nodes = [a.nodes[nid].to_dict() for nid in sorted(removed_node_ids)]

    # Check for modified nodes (same id, different content)
    modified_nodes: list[dict] = []
    for nid in sorted(common_node_ids):
        na = a.nodes[nid]
        nb = b.nodes[nid]
        changes: dict[str, tuple] = {}
        if na.label != nb.label:
            changes["label"] = (na.label, nb.label)
        if na.node_type != nb.node_type:
            changes["node_type"] = (na.node_type, nb.node_type)
        if na.address != nb.address:
            changes["address"] = (na.address, nb.address)
        if na.metadata != nb.metadata:
            changes["metadata"] = (na.metadata, nb.metadata)
        if changes:
            modified_nodes.append({
                "id": nid,
                "changes": {k: {"old": v[0], "new": v[1]} for k, v in changes.items()},
            })

    # --- Edge diff ---
    # Represent edges as comparable tuples
    def _edge_key(e) -> tuple[str, str, str]:
        return (e.src, e.dst, e.edge_type)

    a_edge_set = {_edge_key(e) for e in a.edges}
    b_edge_set = {_edge_key(e) for e in b.edges}

    added_edge_keys = b_edge_set - a_edge_set
    removed_edge_keys = a_edge_set - b_edge_set

    added_edges = [
        {"src": k[0], "dst": k[1], "edge_type": k[2]}
        for k in sorted(added_edge_keys)
    ]
    removed_edges = [
        {"src": k[0], "dst": k[1], "edge_type": k[2]}
        for k in sorted(removed_edge_keys)
    ]

    # --- Summary ---
    parts: list[str] = []
    if added_nodes:
        by_type: dict[str, int] = {}
        for n in added_nodes:
            by_type[n["node_type"]] = by_type.get(n["node_type"], 0) + 1
        type_str = ", ".join(f"{v} {k}" for k, v in sorted(by_type.items()))
        parts.append(f"+{len(added_nodes)} nodes ({type_str})")
    if removed_nodes:
        by_type = {}
        for n in removed_nodes:
            by_type[n["node_type"]] = by_type.get(n["node_type"], 0) + 1
        type_str = ", ".join(f"{v} {k}" for k, v in sorted(by_type.items()))
        parts.append(f"-{len(removed_nodes)} nodes ({type_str})")
    if modified_nodes:
        parts.append(f"~{len(modified_nodes)} modified nodes")
    if added_edges:
        parts.append(f"+{len(added_edges)} edges")
    if removed_edges:
        parts.append(f"-{len(removed_edges)} edges")
    if not parts:
        parts.append("no changes")

    return {
        "added_nodes": added_nodes,
        "removed_nodes": removed_nodes,
        "modified_nodes": modified_nodes,
        "added_edges": added_edges,
        "removed_edges": removed_edges,
        "summary": "; ".join(parts),
    }
