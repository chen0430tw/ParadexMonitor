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
from dataclasses import asdict

from . import __version__

# --- Import modules gracefully (other agents may not have committed yet) ---

try:
    from .detect import detect, FileInfo
except ImportError:
    detect = None  # type: ignore[assignment]

try:
    from .bridges.base import BridgeManager
    from .bridges.qcu_bridge import QCUBridge
    from .bridges.urp_bridge import URPBridge
    from .bridges.exms_bridge import ExMsBridge
    from .bridges.hce_bridge import HCEBridge
    _bridges_available = True
except ImportError:
    _bridges_available = False

try:
    from .topology.callgraph import build_callgraph  # type: ignore[import-untyped]
except ImportError:
    build_callgraph = None  # type: ignore[assignment]

try:
    from .topology.coupling import build_coupling  # type: ignore[import-untyped]
except ImportError:
    build_coupling = None  # type: ignore[assignment]

try:
    from .adapters.pe import PEAdapter  # type: ignore[import-untyped]
except ImportError:
    PEAdapter = None  # type: ignore[assignment]

try:
    from .adapters.elf import ELFAdapter  # type: ignore[import-untyped]
except ImportError:
    ELFAdapter = None  # type: ignore[assignment]

try:
    from .unpack.detect import is_packed  # type: ignore[import-untyped]
except ImportError:
    is_packed = None  # type: ignore[assignment]

try:
    from .propagation import propagate  # type: ignore[import-untyped]
except ImportError:
    propagate = None  # type: ignore[assignment]

# --- Bridge Manager singleton ---

_bridge_mgr: BridgeManager | None = None


def _get_bridge_manager() -> BridgeManager | None:
    global _bridge_mgr
    if _bridge_mgr is not None:
        return _bridge_mgr
    if not _bridges_available:
        return None
    _bridge_mgr = BridgeManager()
    _bridge_mgr.register(QCUBridge())
    _bridge_mgr.register(URPBridge())
    _bridge_mgr.register(ExMsBridge())
    _bridge_mgr.register(HCEBridge())
    return _bridge_mgr


# --- Request handlers ---


def _handle_ping() -> dict:
    mgr = _get_bridge_manager()
    bridges = mgr.available_bridges() if mgr else []
    return {
        "status": "ok",
        "engine": "ppm-engine",
        "version": __version__,
        "bridges": bridges,
    }


def _handle_detect(req: dict) -> dict:
    path = req.get("path", "")
    if not path:
        return {"error": "missing 'path'"}
    if detect is None:
        return {"error": "detect module not available"}
    info = detect(path)
    return {"status": "ok", "command": "detect", "result": asdict(info)}


def _handle_analyze(req: dict) -> dict:
    """Full pipeline: detect -> unpack check -> adapt -> callgraph -> depgraph -> patterns -> reconstruct."""
    path = req.get("path", "")
    if not path:
        return {"error": "missing 'path'"}

    result: dict = {"status": "ok", "command": "analyze", "path": path, "stages": {}}

    # Stage 1: detect
    if detect is None:
        return {"error": "detect module not available"}
    info = detect(path)
    result["stages"]["detect"] = asdict(info)

    if info.format == "NOT_FOUND":
        return {"error": f"file not found: {path}"}

    # Stage 2: unpack check
    if is_packed is not None:
        try:
            packed_result = is_packed(path)
            result["stages"]["unpack"] = {"packed": packed_result}
        except Exception as e:
            result["stages"]["unpack"] = {"error": str(e)}
    else:
        result["stages"]["unpack"] = {"skipped": True, "reason": "unpack module not available"}

    # Stage 3: build adapter
    adapter = None
    fmt = info.format
    if fmt.startswith("PE") and PEAdapter is not None:
        try:
            adapter = PEAdapter(path)
            result["stages"]["adapter"] = {"type": "PE", "loaded": True}
        except Exception as e:
            result["stages"]["adapter"] = {"type": "PE", "error": str(e)}
    elif fmt.startswith("ELF") and ELFAdapter is not None:
        try:
            adapter = ELFAdapter(path)
            result["stages"]["adapter"] = {"type": "ELF", "loaded": True}
        except Exception as e:
            result["stages"]["adapter"] = {"type": "ELF", "error": str(e)}
    else:
        result["stages"]["adapter"] = {"skipped": True, "reason": f"no adapter for {fmt}"}

    # Stage 4: callgraph
    if build_callgraph is not None and adapter is not None:
        try:
            cg = build_callgraph(adapter)
            result["stages"]["callgraph"] = {"nodes": len(cg) if hasattr(cg, '__len__') else "built"}
        except Exception as e:
            result["stages"]["callgraph"] = {"error": str(e)}
    else:
        result["stages"]["callgraph"] = {"skipped": True}

    # Stage 5: coupling / depgraph
    if build_coupling is not None and adapter is not None:
        try:
            dep = build_coupling(adapter)
            result["stages"]["depgraph"] = {"nodes": len(dep) if hasattr(dep, '__len__') else "built"}
        except Exception as e:
            result["stages"]["depgraph"] = {"error": str(e)}
    else:
        result["stages"]["depgraph"] = {"skipped": True}

    # Stage 6: patterns (placeholder)
    result["stages"]["patterns"] = {"skipped": True, "reason": "pattern matching not yet implemented"}

    # Stage 7: propagation / chains
    if propagate is not None and adapter is not None:
        try:
            chains = propagate(adapter)
            result["stages"]["chains"] = {"count": len(chains) if hasattr(chains, '__len__') else "built"}
        except Exception as e:
            result["stages"]["chains"] = {"error": str(e)}
    else:
        result["stages"]["chains"] = {"skipped": True}

    # Architecture summary
    result["summary"] = {
        "format": info.format,
        "arch": info.arch,
        "packed": info.packed,
        "entry_point": hex(info.entry_point) if info.entry_point else "0x0",
        "sections": len(info.sections),
        "import_dlls": len(info.imports),
    }

    return result


def _handle_depgraph(req: dict) -> dict:
    path = req.get("path", "")
    query = req.get("query", "")
    if not path:
        return {"error": "missing 'path'"}

    if detect is None:
        return {"error": "detect module not available"}

    info = detect(path)
    if info.format == "NOT_FOUND":
        return {"error": f"file not found: {path}"}

    # Build adapter
    adapter = None
    fmt = info.format
    if fmt.startswith("PE") and PEAdapter is not None:
        try:
            adapter = PEAdapter(path)
        except Exception as e:
            return {"error": f"PE adapter failed: {e}"}
    elif fmt.startswith("ELF") and ELFAdapter is not None:
        try:
            adapter = ELFAdapter(path)
        except Exception as e:
            return {"error": f"ELF adapter failed: {e}"}

    if adapter is None:
        return {"error": f"no adapter for format {fmt}"}

    if build_coupling is None:
        return {"error": "depgraph/coupling module not available"}

    try:
        graph = build_coupling(adapter)
        result = {"status": "ok", "command": "depgraph", "path": path}
        if query:
            result["query"] = query
            # Basic query: return node neighbors
            if hasattr(graph, 'get'):
                result["result"] = graph.get(query, [])
            else:
                result["result"] = str(graph)
        else:
            result["result"] = str(graph) if not isinstance(graph, dict) else graph
        return result
    except Exception as e:
        return {"error": f"depgraph build failed: {e}"}


def _handle_bridges(req: dict) -> dict:
    mgr = _get_bridge_manager()
    if mgr is None:
        return {"status": "ok", "command": "bridges", "available": [], "error": "bridges module not loaded"}
    return {
        "status": "ok",
        "command": "bridges",
        "available": mgr.available_bridges(),
    }


def handle_request(req: dict) -> dict:
    """Dispatch a single request to the appropriate handler."""
    cmd = req.get("command", "")

    if cmd == "ping":
        return _handle_ping()

    if cmd == "detect":
        return _handle_detect(req)

    if cmd == "analyze":
        return _handle_analyze(req)

    if cmd == "depgraph":
        return _handle_depgraph(req)

    if cmd == "bridges":
        return _handle_bridges(req)

    if cmd == "unpack":
        path = req.get("path", "")
        if not path:
            return {"error": "missing 'path'"}
        if is_packed is not None:
            try:
                packed = is_packed(path)
                return {"status": "ok", "command": "unpack", "path": path, "packed": packed}
            except Exception as e:
                return {"error": str(e)}
        return {"status": "stub", "command": "unpack", "path": path}

    return {"error": f"unknown command: {cmd}"}


def main():
    """Read JSON lines from stdin, write JSON lines to stdout."""
    print(json.dumps({"status": "ready", "engine": "ppm-engine", "version": __version__}),
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
