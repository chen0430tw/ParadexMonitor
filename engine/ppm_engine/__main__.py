"""
PPM Engine — JSON stdin/stdout service loop.

The C++ frontend launches this as a subprocess:
    python -m ppm_engine

Protocol:
    - One JSON object per line on stdin  (request)
    - One JSON object per line on stdout (response)
    - stderr is for diagnostics only (not parsed by frontend)
"""
import sys
import json


def handle_request(req: dict) -> dict:
    """Dispatch a single request to the appropriate handler."""
    cmd = req.get("command", "")

    if cmd == "ping":
        return {"status": "ok", "engine": "ppm-engine", "version": "0.1.0"}

    if cmd == "analyze":
        path = req.get("path", "")
        if not path:
            return {"error": "missing 'path'"}
        # Phase 2: detect → unpack → topology → reconstruct
        return {"status": "stub", "command": "analyze", "path": path,
                "message": "analysis pipeline not yet implemented"}

    if cmd == "depgraph":
        path = req.get("path", "")
        query = req.get("query", "")
        return {"status": "stub", "command": "depgraph", "path": path,
                "query": query, "message": "depgraph not yet implemented"}

    if cmd == "detect":
        path = req.get("path", "")
        return {"status": "stub", "command": "detect", "path": path}

    if cmd == "unpack":
        path = req.get("path", "")
        return {"status": "stub", "command": "unpack", "path": path}

    return {"error": f"unknown command: {cmd}"}


def main():
    """Read JSON lines from stdin, write JSON lines to stdout."""
    print(json.dumps({"status": "ready", "engine": "ppm-engine", "version": "0.1.0"}),
          flush=True)

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except json.JSONDecodeError as e:
            resp = {"error": f"invalid JSON: {e}"}
        else:
            try:
                resp = handle_request(req)
            except Exception as e:
                resp = {"error": str(e)}

        print(json.dumps(resp), flush=True)


if __name__ == "__main__":
    main()
