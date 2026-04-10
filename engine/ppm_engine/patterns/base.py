"""
Base classes for the pattern matching engine.

Each Pattern subclass scans a binary (via a PEAdapter) for a specific
known behavior and returns PatternMatch objects with confidence scores.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    pass


@dataclass
class PatternMatch:
    pattern_name: str
    confidence: float     # 0.0 - 1.0
    location: int         # RVA where pattern was found
    details: dict         # pattern-specific info
    description: str      # human-readable explanation


class Pattern(ABC):
    @property
    @abstractmethod
    def name(self) -> str:
        ...

    @abstractmethod
    def scan(self, adapter, callgraph=None, depgraph=None) -> list[PatternMatch]:
        """Scan binary for this pattern. Return matches."""
        ...


class PatternEngine:
    """Run all registered patterns against a binary."""

    def __init__(self):
        self.patterns: list[Pattern] = []

    def register(self, pattern: Pattern):
        self.patterns.append(pattern)

    def register_defaults(self):
        """Register all built-in patterns."""
        from .ob_callback import ObCallbackPattern
        from .cm_callback import CmCallbackPattern
        from .apc_inject import ApcInjectPattern
        from .dkom import DkomPattern
        from .handle_strip import HandleStripPattern

        for cls in (ObCallbackPattern, CmCallbackPattern, ApcInjectPattern,
                    DkomPattern, HandleStripPattern):
            self.register(cls())

    def scan_all(self, adapter, callgraph=None, depgraph=None) -> list[PatternMatch]:
        results: list[PatternMatch] = []
        self.errors: list[dict] = []
        for p in self.patterns:
            try:
                results.extend(p.scan(adapter, callgraph, depgraph))
            except Exception as e:
                # Log errors but don't create fake matches
                self.errors.append({"pattern": p.name, "error": str(e)})
        return sorted(results, key=lambda m: -m.confidence)
