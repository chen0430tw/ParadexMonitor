"""Bridge to exMs Linux compatibility layer for ELF syscall emulation."""
from .base import IBridge
import os


class ExMsBridge(IBridge):
    def __init__(self, exms_path: str = ""):
        self.exms_path = exms_path or os.environ.get("EXMS_PATH", "")

    @property
    def name(self) -> str:
        return "exms"

    def available(self) -> bool:
        return bool(self.exms_path) and os.path.isdir(self.exms_path)

    def call(self, request: dict) -> dict:
        return {"status": "stub", "message": "exMs bridge not yet implemented"}
