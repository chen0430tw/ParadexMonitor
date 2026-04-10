"""
Render a DepGraph to Graphviz DOT or ASCII tree format.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ppm_engine.depgraph.query import DepGraph


# Color scheme for DOT output
_NODE_COLORS = {
    "function": "lightblue",
    "import": "lightgreen",
    "callback": "salmon",
    "string": "lightyellow",
    "global": "lavender",
}

_EDGE_STYLES = {
    "calls": "solid",
    "registers": "bold",
    "references": "dashed",
    "passes_arg": "dotted",
}

_EDGE_COLORS = {
    "calls": "black",
    "registers": "red",
    "references": "gray",
    "passes_arg": "blue",
}


def to_dot(graph: DepGraph) -> str:
    """Convert DepGraph to Graphviz DOT with color-coded node types.

    Node colors:
        - function: lightblue
        - import: lightgreen
        - callback: salmon
        - string: lightyellow
        - global: lavender
    """
    lines: list[str] = []
    lines.append("digraph DepGraph {")
    lines.append('    rankdir=TB;')
    lines.append('    node [shape=box, style=filled, fontname="Consolas"];')
    lines.append('    edge [fontname="Consolas", fontsize=9];')
    lines.append("")

    # Nodes
    for nid, node in graph.nodes.items():
        color = _NODE_COLORS.get(node.node_type, "white")
        # Escape label for DOT
        label = node.label.replace('"', '\\"').replace("\n", "\\n")
        if len(label) > 40:
            label = label[:37] + "..."
        shape = "ellipse" if node.node_type == "import" else "box"
        if node.node_type == "callback":
            shape = "octagon"
        elif node.node_type == "string":
            shape = "note"

        safe_id = _dot_id(nid)
        lines.append(
            f'    {safe_id} [label="{label}", '
            f'fillcolor="{color}", shape={shape}, '
            f'tooltip="{nid}"];'
        )

    lines.append("")

    # Edges
    for edge in graph.edges:
        src = _dot_id(edge.src)
        dst = _dot_id(edge.dst)
        style = _EDGE_STYLES.get(edge.edge_type, "solid")
        color = _EDGE_COLORS.get(edge.edge_type, "black")
        label = edge.edge_type if edge.edge_type != "calls" else ""
        label_attr = f', label="{label}"' if label else ""
        lines.append(
            f'    {src} -> {dst} [style={style}, color="{color}"{label_attr}];'
        )

    lines.append("}")
    return "\n".join(lines)


def _dot_id(node_id: str) -> str:
    """Convert a node ID to a valid DOT identifier."""
    # Replace non-alphanumeric chars with underscore
    safe = ""
    for c in node_id:
        if c.isalnum() or c == "_":
            safe += c
        else:
            safe += "_"
    # DOT ids can't start with a digit
    if safe and safe[0].isdigit():
        safe = "n" + safe
    return safe


def to_ascii_tree(graph: DepGraph, root_id: str, max_depth: int = 5) -> str:
    """Render the graph as an indented ASCII tree from *root_id*.

    Example output::

        DriverEntry
        +-- ObRegisterCallbacks
        |   \\-- registers -> PreOp(0x78B8)
        +-- CmRegisterCallbackEx
        |   \\-- registers -> CmCb(0x7C20)
        \\-- PsSetLoadImageNotifyRoutine
    """
    if root_id not in graph.nodes:
        return f"(node {root_id!r} not found)"

    lines: list[str] = []
    _ascii_recurse(graph, root_id, "", True, max_depth, 0, set(), lines)
    return "\n".join(lines)


def _ascii_recurse(
    graph: DepGraph,
    node_id: str,
    prefix: str,
    is_last: bool,
    max_depth: int,
    depth: int,
    visited: set[str],
    lines: list[str],
) -> None:
    """Recursively build ASCII tree lines."""
    node = graph.nodes.get(node_id)
    if node is None:
        return

    # Build the current line
    if depth == 0:
        connector = ""
        child_prefix = ""
    else:
        connector = "\\-- " if is_last else "+-- "
        child_prefix = prefix + ("    " if is_last else "|   ")

    label = node.label
    if node.node_type == "import":
        label = f"[{label}]"
    elif node.node_type == "callback":
        label = f"<{label}>"
    elif node.node_type == "string":
        display = node.label[:30] + "..." if len(node.label) > 30 else node.label
        label = f'"{display}"'

    lines.append(f"{prefix}{connector}{label}")

    if depth >= max_depth:
        return
    if node_id in visited:
        lines.append(f"{child_prefix}(cycle)")
        return

    visited = visited | {node_id}

    # Get children (outgoing edges)
    children: list[tuple[str, str]] = []  # (edge_type, dst_id)
    for edge in graph.outgoing.get(node_id, []):
        if edge.dst in graph.nodes:
            children.append((edge.edge_type, edge.dst))

    for i, (edge_type, dst_id) in enumerate(children):
        child_is_last = (i == len(children) - 1)

        # For non-"calls" edges, show the edge type as annotation
        if edge_type != "calls":
            dst_node = graph.nodes[dst_id]
            ann_connector = "\\-- " if child_is_last else "+-- "
            ann_label = f"{edge_type} -> {dst_node.label}"
            lines.append(f"{child_prefix}{ann_connector}{ann_label}")
        else:
            _ascii_recurse(
                graph, dst_id, child_prefix, child_is_last,
                max_depth, depth + 1, visited, lines,
            )
