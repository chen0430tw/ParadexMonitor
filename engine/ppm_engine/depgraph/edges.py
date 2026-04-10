"""Edge types for the dependency graph."""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Edge:
    """A directed edge in the dependency graph.

    Attributes:
        src:       Source node ID.
        dst:       Destination node ID.
        edge_type: One of ``"calls"``, ``"registers"``, ``"references"``,
                   ``"passes_arg"``.
        metadata:  Arbitrary key-value metadata.
    """
    src: str
    dst: str
    edge_type: str  # "calls", "registers", "references", "passes_arg"
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "src": self.src,
            "dst": self.dst,
            "edge_type": self.edge_type,
            "metadata": self.metadata,
        }
