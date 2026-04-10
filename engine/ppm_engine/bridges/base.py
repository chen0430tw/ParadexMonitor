from abc import ABC, abstractmethod


class IBridge(ABC):
    """Interface for external system bridges. All bridges are optional."""

    @property
    @abstractmethod
    def name(self) -> str: ...

    @abstractmethod
    def available(self) -> bool:
        """Check if the external system is reachable/installed."""
        ...

    @abstractmethod
    def call(self, request: dict) -> dict:
        """Send request, get response."""
        ...


class BridgeManager:
    """Auto-detect and manage available bridges."""

    def __init__(self):
        self._bridges: dict[str, IBridge] = {}

    def register(self, bridge: IBridge):
        self._bridges[bridge.name] = bridge

    def detect_all(self):
        """Check availability of all registered bridges."""
        for name, b in self._bridges.items():
            try:
                if b.available():
                    print(f"[bridge] {name}: available", flush=True)
                else:
                    print(f"[bridge] {name}: not available", flush=True)
            except Exception:
                print(f"[bridge] {name}: error during detection", flush=True)

    def get(self, name: str) -> IBridge | None:
        b = self._bridges.get(name)
        if b and b.available():
            return b
        return None

    def available_bridges(self) -> list[str]:
        return [n for n, b in self._bridges.items() if b.available()]
