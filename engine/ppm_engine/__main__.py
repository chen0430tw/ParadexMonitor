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
    from .adapters.pe import PEAdapter
except ImportError:
    PEAdapter = None  # type: ignore[assignment]

try:
    from .adapters.elf import ELFAdapter
except ImportError:
    ELFAdapter = None  # type: ignore[assignment]

try:
    from .adapters.lnk import LNKAdapter
except ImportError:
    LNKAdapter = None  # type: ignore[assignment]

try:
    from .adapters.macho import MachOAdapter
except ImportError:
    MachOAdapter = None  # type: ignore[assignment]

try:
    from .unpack.detect import detect_packer
except ImportError:
    detect_packer = None  # type: ignore[assignment]

try:
    from .topology.callgraph import CallGraph
except ImportError:
    CallGraph = None  # type: ignore[assignment]

try:
    from .depgraph.build import DepGraphBuilder
except ImportError:
    DepGraphBuilder = None  # type: ignore[assignment]

try:
    from .patterns.base import PatternEngine
except ImportError:
    PatternEngine = None  # type: ignore[assignment]

try:
    from .propagation.chain import ChainTracer
except ImportError:
    ChainTracer = None  # type: ignore[assignment]

try:
    from .reconstruct.architecture import ArchitectureReconstructor
except ImportError:
    ArchitectureReconstructor = None  # type: ignore[assignment]

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


# --- Path sanitization ---

def _sanitize_path(path: str) -> str:
    """Strip dangerous characters from user-supplied paths.

    Prevents injection payloads from leaking into JSON output and
    blocks protocol-based paths (http://, file://, \\\\UNC).
    """
    # Block protocol-based paths
    lower = path.lower().strip()
    for proto in ("http://", "https://", "ftp://", "file://", "ldap://", "jndi:"):
        if proto in lower:
            raise ValueError(f"protocol in path not allowed: {proto}")
    # Block UNC paths
    if path.startswith("\\\\") or path.startswith("//"):
        raise ValueError("UNC paths not allowed")
    # Block Windows reserved device names (CON, NUL, PRN, AUX, COM1-9, LPT1-9)
    # These can cause hangs or unexpected behavior when opened
    import re
    basename = path.rsplit("\\", 1)[-1].rsplit("/", 1)[-1].split(".")[0].upper()
    if re.fullmatch(r"CON|NUL|PRN|AUX|COM\d|LPT\d", basename):
        raise ValueError(f"Windows reserved device name not allowed: {basename}")
    # Strip control characters and Unicode direction overrides
    cleaned = "".join(c for c in path if ord(c) >= 0x20 and ord(c) not in (0x202A, 0x202B, 0x202C, 0x202D, 0x202E, 0x2066, 0x2067, 0x2068, 0x2069))
    # Strip null bytes
    cleaned = cleaned.replace("\x00", "")
    return cleaned


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
    try:
        path = _sanitize_path(path)
    except ValueError as e:
        return {"error": str(e)}
    if detect is None:
        return {"error": "detect module not available"}
    info = detect(path)
    return {"status": "ok", "command": "detect", "result": asdict(info)}


def _handle_analyze(req: dict) -> dict:
    """Full pipeline: detect -> unpack -> adapt -> callgraph -> depgraph -> patterns -> chains -> reconstruct."""
    path = req.get("path", "")
    if not path:
        return {"error": "missing 'path'"}
    try:
        path = _sanitize_path(path)
    except ValueError as e:
        return {"error": str(e)}

    result: dict = {"status": "ok", "command": "analyze", "path": path, "stages": {}}

    # Stage 1: detect
    if detect is None:
        return {"error": "detect module not available"}
    info = detect(path)
    result["stages"]["detect"] = asdict(info)
    if info.format == "NOT_FOUND":
        return {"error": f"file not found: {path}"}

    # Stage 2: unpack check
    if detect_packer is not None:
        try:
            pack_info = detect_packer(path)
            result["stages"]["unpack"] = pack_info
        except Exception as e:
            result["stages"]["unpack"] = {"error": str(e)}
    else:
        result["stages"]["unpack"] = {"skipped": True, "reason": "unpack.detect not available"}

    # Stage 3: build adapter
    adapter = None
    fmt = info.format
    if fmt == "LNK" and LNKAdapter is not None:
        # LNK files are shortcuts, not binaries -- run LNK-specific analysis
        try:
            lnk = LNKAdapter(path)
            lnk_result = lnk.summary()
            lnk_result["risk"] = lnk.analyze_risk()
            lnk_result["strings"] = lnk.strings()
            result["stages"]["adapter"] = {"type": "LNK", **lnk_result}
            # LNK files skip binary analysis stages
            for stage in ("callgraph", "depgraph", "patterns", "chains", "architecture"):
                result["stages"][stage] = {"skipped": True, "reason": "LNK shortcut file"}
            result["summary"] = {
                "format": "LNK", "arch": "n/a", "packed": False,
                "target": lnk_result["target"],
                "arguments": lnk_result["arguments"][:100],
                "risk": lnk_result["risk"]["classification"],
                "stages_completed": 2, "stages_total": 8,
            }
            return result
        except Exception as e:
            result["stages"]["adapter"] = {"type": "LNK", "error": str(e)}
            return result
    elif fmt.startswith("PE") and PEAdapter is not None:
        try:
            adapter = PEAdapter(path)
            result["stages"]["adapter"] = {
                "type": "PE",
                "imports": {k: len(v) for k, v in adapter.imports().items()},
                "iat_calls": len(adapter.iat_calls()),
                "strings": len(adapter.strings()),
                "is_driver": adapter.is_driver(),
            }
        except Exception as e:
            result["stages"]["adapter"] = {"type": "PE", "error": str(e)}
    elif fmt.startswith("ELF") and ELFAdapter is not None:
        try:
            adapter = ELFAdapter(path)
            result["stages"]["adapter"] = {
                "type": "ELF",
                "imports": {k: len(v) for k, v in adapter.imports().items()},
                "strings": len(adapter.strings()),
                "is_kernel_module": adapter.is_kernel_module(),
            }
        except Exception as e:
            result["stages"]["adapter"] = {"type": "ELF", "error": str(e)}
    elif fmt.startswith("MACHO") and MachOAdapter is not None:
        try:
            adapter = MachOAdapter(path)
            result["stages"]["adapter"] = {
                "type": "MachO",
                "imports": {k: len(v) for k, v in adapter.imports().items()},
                "strings": len(adapter.strings()),
                "is_kext": adapter.is_kernel_extension(),
            }
        except Exception as e:
            result["stages"]["adapter"] = {"type": "MachO", "error": str(e)}
    else:
        result["stages"]["adapter"] = {"skipped": True, "reason": f"no adapter for {fmt}"}

    # Stage 4: callgraph
    cg = None
    if CallGraph is not None and adapter is not None:
        try:
            cg = CallGraph.from_pe(adapter)
            result["stages"]["callgraph"] = {
                "functions": len(cg.functions),
                "roots": len(cg.roots()),
                "leaves": len(cg.leaves()),
            }
        except Exception as e:
            result["stages"]["callgraph"] = {"error": str(e)}
    else:
        result["stages"]["callgraph"] = {"skipped": True, "reason": "CallGraph or adapter not available"}

    # Stage 5: depgraph
    graph = None
    if DepGraphBuilder is not None and cg is not None and adapter is not None:
        try:
            builder = DepGraphBuilder()
            graph = builder.build(cg, adapter)
            result["stages"]["depgraph"] = {
                "nodes": len(graph.nodes),
                "edges": len(graph.edges),
            }
        except Exception as e:
            result["stages"]["depgraph"] = {"error": str(e)}
    else:
        result["stages"]["depgraph"] = {"skipped": True, "reason": "DepGraphBuilder, callgraph, or adapter not available"}

    # Stage 6: pattern matching
    if PatternEngine is not None and adapter is not None:
        try:
            engine = PatternEngine()
            engine.register_defaults()
            matches = engine.scan_all(adapter, cg, graph)
            result["stages"]["patterns"] = {
                "matches": [
                    {"pattern": m.pattern_name, "confidence": m.confidence,
                     "location": hex(m.location), "description": m.description}
                    for m in matches
                ]
            }
            # Inject pattern results back into depgraph nodes
            if graph is not None:
                for m in matches:
                    best_node = None
                    best_dist = float("inf")
                    for nid, node in graph.nodes.items():
                        if node.node_type not in ("function", "callback"):
                            continue
                        # Exact address match
                        if node.address == m.location:
                            best_node = node
                            break
                        # Pattern location falls within function range (call site inside function)
                        fn_size = node.metadata.get("size", 0)
                        if fn_size and node.address <= m.location < node.address + fn_size:
                            dist = m.location - node.address
                            if dist < best_dist:
                                best_dist = dist
                                best_node = node
                    if best_node is not None:
                        best_node.metadata.setdefault("patterns", []).append({
                            "name": m.pattern_name,
                            "confidence": m.confidence,
                            "description": m.description,
                        })
        except Exception as e:
            result["stages"]["patterns"] = {"error": str(e)}
    else:
        result["stages"]["patterns"] = {"skipped": True, "reason": "PatternEngine or adapter not available"}

    # Stage 7: propagation / chains
    if ChainTracer is not None and graph is not None:
        try:
            tracer = ChainTracer(graph)
            chains = tracer.all_interesting_chains()
            result["stages"]["chains"] = {
                "count": len(chains),
                "chains": [c.to_dict() for c in chains[:20]],  # cap at 20
            }
        except Exception as e:
            result["stages"]["chains"] = {"error": str(e)}
    else:
        result["stages"]["chains"] = {"skipped": True, "reason": "ChainTracer or depgraph not available"}

    # Stage 8: architecture reconstruction
    if ArchitectureReconstructor is not None and adapter is not None:
        try:
            recon = ArchitectureReconstructor()
            arch = recon.summarize(
                asdict(info),
                graph,
                result["stages"].get("chains", {}).get("chains", [])
            )
            result["stages"]["architecture"] = arch
        except Exception as e:
            result["stages"]["architecture"] = {"error": str(e)}
    else:
        result["stages"]["architecture"] = {"skipped": True}

    # Top-level summary
    result["summary"] = {
        "format": info.format,
        "arch": info.arch,
        "packed": info.packed,
        "entry_point": hex(info.entry_point) if info.entry_point else "0x0",
        "sections": len(info.sections),
        "import_dlls": len(info.imports),
        "stages_completed": sum(1 for s in result["stages"].values()
                                if not (isinstance(s, dict) and s.get("skipped"))),
        "stages_total": len(result["stages"]),
    }

    return result


def _handle_depgraph(req: dict) -> dict:
    path = req.get("path", "")
    query = req.get("query", "")
    if not path:
        return {"error": "missing 'path'"}
    try:
        path = _sanitize_path(path)
    except ValueError as e:
        return {"error": str(e)}
    if detect is None:
        return {"error": "detect module not available"}
    if CallGraph is None or DepGraphBuilder is None:
        return {"error": "topology/depgraph modules not available"}

    info = detect(path)
    if info.format == "NOT_FOUND":
        return {"error": f"file not found: {path}"}

    # Build adapter
    adapter = None
    if info.format.startswith("PE") and PEAdapter is not None:
        adapter = PEAdapter(path)
    elif info.format.startswith("ELF") and ELFAdapter is not None:
        adapter = ELFAdapter(path)
    if adapter is None:
        return {"error": f"no adapter for {info.format}"}

    try:
        cg = CallGraph.from_pe(adapter)
        graph = DepGraphBuilder().build(cg, adapter)
        result: dict = {"status": "ok", "command": "depgraph", "path": path,
                        "nodes": len(graph.nodes), "edges": len(graph.edges)}

        if query:
            result["query"] = query
            q = query.strip()
            if q.startswith("who_registers"):
                arg = q.split(None, 1)[1] if " " in q else ""
                result["result"] = graph.who_registers(arg)
            elif q.startswith("find_sinks"):
                arg = q.split(None, 1)[1] if " " in q else ""
                chains = graph.find_sinks(arg)
                result["result"] = [list(c) for c in chains[:20]]
            elif q.startswith("impact_of"):
                arg = q.split(None, 1)[1] if " " in q else ""
                result["result"] = graph.impact_of(arg)
            elif q.startswith("trace_from"):
                arg = q.split(None, 1)[1] if " " in q else ""
                result["result"] = graph.trace_from(arg)
            else:
                result["result"] = {"error": f"unknown query: {q}"}
        else:
            result["ascii"] = graph.to_ascii()

        return result
    except Exception as e:
        return {"error": f"depgraph failed: {e}"}


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
