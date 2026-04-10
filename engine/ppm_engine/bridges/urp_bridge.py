"""Bridge to URP/URX Runtime for distributed analysis scheduling.
Converts analysis tasks into IRGraph and dispatches to URP nodes."""

import socket
import struct
import json
from .base import IBridge


class URPBridge(IBridge):
    def __init__(self, host="127.0.0.1", port=9000):
        self.host = host
        self.port = port

    @property
    def name(self) -> str:
        return "urp"

    def available(self) -> bool:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            s.connect((self.host, self.port))
            s.close()
            return True
        except (ConnectionRefusedError, TimeoutError, OSError):
            return False

    def call(self, request: dict) -> dict:
        """Send IRGraph JSON to URP node, get execution result."""
        try:
            payload = json.dumps(request).encode("utf-8")
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(30)
            s.connect((self.host, self.port))
            # URP framing: 4-byte BE length prefix
            s.sendall(struct.pack(">I", len(payload)) + payload)
            # Read response
            hdr = s.recv(4)
            if len(hdr) < 4:
                return {"error": "URP connection closed"}
            resp_len = struct.unpack(">I", hdr)[0]
            resp_data = b""
            while len(resp_data) < resp_len:
                chunk = s.recv(min(resp_len - len(resp_data), 8192))
                if not chunk:
                    break
                resp_data += chunk
            s.close()
            return json.loads(resp_data)
        except Exception as e:
            return {"error": str(e)}
