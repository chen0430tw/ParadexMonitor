"""Bridge to HCE unified orchestration layer."""
from .base import IBridge


class HCEBridge(IBridge):
    @property
    def name(self) -> str:
        return "hce"

    def available(self) -> bool:
        return False  # Reserved for future

    def call(self, request: dict) -> dict:
        return {"status": "stub", "message": "HCE bridge reserved for future"}
