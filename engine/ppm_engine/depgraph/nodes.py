"""Node types for the dependency graph."""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Node:
    """A single node in the dependency graph.

    Attributes:
        id:        Unique identifier (e.g. ``"func_0x1458"``, ``"import_ObRegisterCallbacks"``).
        address:   Virtual address or RVA in the binary.
        label:     Human-readable display name.
        node_type: One of ``"function"``, ``"import"``, ``"callback"``,
                   ``"global"``, ``"string"``.
        metadata:  Arbitrary key-value metadata (e.g. dll name, encoding).
    """
    id: str
    address: int
    label: str
    node_type: str  # "function", "import", "callback", "global", "string"
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "address": self.address,
            "label": self.label,
            "node_type": self.node_type,
            "metadata": self.metadata,
        }
