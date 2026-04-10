"""
Human-friendly CLI for ppm-engine.

Usage:
    ppm detect <file>
    ppm analyze <file>
    ppm depgraph <file> [--query "who_registers ObCallback"]
    ppm dataflow <file> [--api ObOpenObjectByPointer]
    ppm pseudo <file> <rva>
    ppm strings <file> [--min-len 8]
    ppm imports <file>
    ppm tree <file>
    ppm dot <file> [-o graph.dot]
    ppm risk <file.lnk>
"""
from __future__ import annotations

import sys
import os
import json
import argparse
from dataclasses import asdict


def main(argv: list[str] | None = None):
    parser = argparse.ArgumentParser(
        prog="ppm",
        description="Paradex Process Monitor -- binary analysis engine",
    )
    parser.add_argument("--version", action="store_true", help="Show version")
    parser.add_argument("--json", action="store_true", help="Output raw JSON")

    sub = parser.add_subparsers(dest="command")

    # detect
    p = sub.add_parser("detect", help="Detect file format")
    p.add_argument("file", help="Path to binary")

    # analyze
    p = sub.add_parser("analyze", help="Full 8-stage pipeline analysis")
    p.add_argument("file", help="Path to binary")

    # imports
    p = sub.add_parser("imports", help="List imports")
    p.add_argument("file", help="Path to binary")

    # strings
    p = sub.add_parser("strings", help="Extract strings")
    p.add_argument("file", help="Path to binary")
    p.add_argument("--min-len", type=int, default=6, help="Minimum string length")

    # tree
    p = sub.add_parser("tree", help="ASCII call tree from entry point")
    p.add_argument("file", help="Path to binary")
    p.add_argument("--depth", type=int, default=6, help="Max tree depth")

    # dot
    p = sub.add_parser("dot", help="Generate Graphviz DOT")
    p.add_argument("file", help="Path to binary")
    p.add_argument("-o", "--output", help="Write to file instead of stdout")

    # depgraph
    p = sub.add_parser("depgraph", help="Dependency graph queries")
    p.add_argument("file", help="Path to binary")
    p.add_argument("--query", "-q", help="Query: who_registers, find_sinks, trace_from, impact_of")

    # dataflow
    p = sub.add_parser("dataflow", help="Track API argument values")
    p.add_argument("file", help="Path to binary")
    p.add_argument("--api", nargs="*", help="API names to track (default: all interesting)")

    # pseudo
    p = sub.add_parser("pseudo", help="Generate pseudo-code for a function")
    p.add_argument("file", help="Path to binary")
    p.add_argument("rva", help="Function RVA (hex, e.g. 0x78B8)")

    # risk (LNK)
    p = sub.add_parser("risk", help="Analyze LNK shortcut risk")
    p.add_argument("file", help="Path to .lnk file")

    args = parser.parse_args(argv)

    if args.version:
        from ppm_engine import __version__
        print(f"ppm-engine {__version__}")
        return

    if not args.command:
        parser.print_help()
        return

    try:
        _dispatch(args)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


def _dispatch(args):
    cmd = args.command

    if cmd == "detect":
        _cmd_detect(args)
    elif cmd == "analyze":
        _cmd_analyze(args)
    elif cmd == "imports":
        _cmd_imports(args)
    elif cmd == "strings":
        _cmd_strings(args)
    elif cmd == "tree":
        _cmd_tree(args)
    elif cmd == "dot":
        _cmd_dot(args)
    elif cmd == "depgraph":
        _cmd_depgraph(args)
    elif cmd == "dataflow":
        _cmd_dataflow(args)
    elif cmd == "pseudo":
        _cmd_pseudo(args)
    elif cmd == "risk":
        _cmd_risk(args)


# ------------------------------------------------------------------
# Commands
# ------------------------------------------------------------------

def _cmd_detect(args):
    from ppm_engine.detect import detect
    info = detect(args.file)
    if args.json:
        print(json.dumps(asdict(info), indent=2))
    else:
        name = os.path.basename(args.file)
        print(f"{name}: {info.format}, {info.arch}, packed={info.packed}")
        if info.packer:
            print(f"  Packer: {info.packer}")
        if info.sections:
            print(f"  Sections: {len(info.sections)}")
        if info.imports:
            total = sum(len(v) for v in info.imports.values())
            print(f"  Imports: {total} from {len(info.imports)} libraries")


def _cmd_analyze(args):
    from ppm_engine.__main__ import handle_request
    resp = handle_request({"command": "analyze", "path": args.file})

    if args.json:
        print(json.dumps(resp, indent=2))
        return

    if "error" in resp:
        print(f"Error: {resp['error']}")
        return

    s = resp.get("summary", {})
    stages = resp.get("stages", {})

    print(f"{os.path.basename(args.file)}: {s.get('format','?')}, {s.get('arch','?')}, packed={s.get('packed',False)}")

    # Adapter
    ad = stages.get("adapter", {})
    if not ad.get("skipped"):
        atype = ad.get("type", "?")
        if atype == "LNK":
            print(f"  Target: {ad.get('target','?')}")
            print(f"  Args: {ad.get('arguments','')[:80]}")
            risk = ad.get("risk", {})
            if risk:
                print(f"  Risk: {risk.get('classification','?')} ({risk.get('risk',0)})")
            return
        imports = ad.get("imports", {})
        total = sum(imports.values()) if isinstance(imports, dict) else 0
        print(f"  Imports: {total} from {len(imports)} libraries")

    # Callgraph
    cg = stages.get("callgraph", {})
    if not cg.get("skipped"):
        print(f"  Functions: {cg.get('functions',0)}, roots: {cg.get('roots',0)}")

    # Depgraph
    dg = stages.get("depgraph", {})
    if not dg.get("skipped"):
        print(f"  Depgraph: {dg.get('nodes',0)} nodes, {dg.get('edges',0)} edges")

    # Patterns
    pat = stages.get("patterns", {})
    if not pat.get("skipped"):
        matches = pat.get("matches", [])
        if matches:
            print(f"  Patterns:")
            for m in matches:
                print(f"    {m['pattern']} (conf={m['confidence']}) @ {m['location']}")
        else:
            print(f"  Patterns: none")

    # Chains
    ch = stages.get("chains", {})
    if not ch.get("skipped"):
        chains = ch.get("chains", [])
        if chains:
            verdicts = {}
            for c in chains:
                v = c.get("verdict", "?")
                verdicts[v] = verdicts.get(v, 0) + 1
            print(f"  Chains ({ch.get('count',0)}):")
            for v, n in sorted(verdicts.items(), key=lambda x: -x[1]):
                print(f"    {v}: {n}")

    # Architecture
    arch = stages.get("architecture", {})
    if not arch.get("skipped") and not arch.get("error"):
        print(f"  Type: {arch.get('type','?')}")
        print(f"  {arch.get('summary','')}")
        for sp in arch.get("self_protection", []):
            print(f"  Self-prot: {sp}")

    completed = s.get("stages_completed", 0)
    total = s.get("stages_total", 0)
    print(f"  [{completed}/{total} stages]")


def _cmd_imports(args):
    adapter = _make_adapter(args.file)
    imports = adapter.imports()

    if args.json:
        print(json.dumps(imports, indent=2))
        return

    total = sum(len(v) for v in imports.values())
    print(f"{os.path.basename(args.file)}: {total} imports from {len(imports)} libraries")
    for lib, funcs in imports.items():
        print(f"\n  {lib} ({len(funcs)}):")
        for f in funcs:
            print(f"    {f}")


def _cmd_strings(args):
    adapter = _make_adapter(args.file)
    strings = adapter.strings(min_len=args.min_len)

    if args.json:
        print(json.dumps(strings, indent=2))
        return

    print(f"{os.path.basename(args.file)}: {len(strings)} strings (min_len={args.min_len})")
    for s in strings:
        rva = s.get("rva", 0)
        val = s["value"]
        if len(val) > 100:
            val = val[:97] + "..."
        print(f"  {rva:#06x}: {val}")


def _cmd_tree(args):
    adapter = _make_adapter(args.file)
    from ppm_engine.topology.callgraph import CallGraph
    from ppm_engine.depgraph.build import DepGraphBuilder

    cg = CallGraph.from_pe(adapter)
    graph = DepGraphBuilder().build(cg, adapter)
    print(graph.to_ascii())


def _cmd_dot(args):
    adapter = _make_adapter(args.file)
    from ppm_engine.topology.callgraph import CallGraph
    from ppm_engine.depgraph.build import DepGraphBuilder

    cg = CallGraph.from_pe(adapter)
    graph = DepGraphBuilder().build(cg, adapter)
    dot = graph.to_dot()

    if args.output:
        with open(args.output, "w") as f:
            f.write(dot)
        print(f"Written to {args.output} ({len(dot.splitlines())} lines)")
    else:
        print(dot)


def _cmd_depgraph(args):
    adapter = _make_adapter(args.file)
    from ppm_engine.topology.callgraph import CallGraph
    from ppm_engine.depgraph.build import DepGraphBuilder

    cg = CallGraph.from_pe(adapter)
    graph = DepGraphBuilder().build(cg, adapter)

    if not args.query:
        print(f"{len(graph.nodes)} nodes, {len(graph.edges)} edges")
        print(f"Use --query, e.g.:")
        print(f'  ppm depgraph {args.file} -q "who_registers ObCallback"')
        print(f'  ppm depgraph {args.file} -q "find_sinks ZwTerminateProcess"')
        print(f'  ppm depgraph {args.file} -q "trace_from func_0x1458"')
        print(f'  ppm depgraph {args.file} -q "impact_of func_0x78B8"')
        return

    q = args.query.strip()
    parts = q.split(None, 1)
    cmd = parts[0]
    arg = parts[1] if len(parts) > 1 else ""

    if cmd == "who_registers":
        results = graph.who_registers(arg)
        if not results:
            print(f"No registrations found for '{arg}'")
        for r in results:
            print(f"  {r['registrar']} -> {r['handler']} ({r['type']})")

    elif cmd == "find_sinks":
        chains = graph.find_sinks(arg)
        if not chains:
            print(f"No chains found to '{arg}'")
        for chain in chains:
            labels = [graph.nodes[n].label if n in graph.nodes else n for n in chain]
            print(f"  {' -> '.join(labels)}")

    elif cmd == "trace_from":
        tree = graph.trace_from(arg, depth=6)
        if not tree:
            print(f"Node '{arg}' not found")
        else:
            _print_tree(tree)

    elif cmd == "impact_of":
        impact = graph.impact_of(arg)
        if not impact.get("affected"):
            print(f"No downstream impact from '{arg}'")
        else:
            print(f"  {impact['affected_count']} affected nodes:")
            for ntype, nids in impact.get("by_type", {}).items():
                print(f"    {ntype}: {len(nids)}")

    else:
        print(f"Unknown query: {cmd}")
        print(f"Available: who_registers, find_sinks, trace_from, impact_of")


def _cmd_dataflow(args):
    adapter = _make_adapter(args.file)
    from ppm_engine.topology.callgraph import CallGraph
    from ppm_engine.topology.dataflow import track_all_interesting, track_arguments

    cg = CallGraph.from_pe(adapter)

    text_sec = None
    for sec in adapter._pe.sections:
        if b".text" in sec.Name:
            text_sec = sec
            break
    if not text_sec:
        print("Error: no .text section")
        return

    text_data = text_sec.get_data()
    text_base = text_sec.VirtualAddress

    if args.api:
        results = {}
        for api in args.api:
            for addr, fn in cg.functions.items():
                if fn.is_import and fn.import_name == api:
                    tracked = track_arguments(cg, addr, text_data, text_base)
                    if tracked:
                        results[api] = tracked
    else:
        results = track_all_interesting(cg, text_data, text_base)

    if args.json:
        # Convert int keys to strings for JSON
        out = {}
        for api, sites in results.items():
            out[api] = {hex(k): v for k, v in sites.items()}
        print(json.dumps(out, indent=2))
        return

    if not results:
        print("No dataflow results (no interesting API calls found)")
        return

    for api, sites in results.items():
        print(f"{api}:")
        for addr, arg_list in sites.items():
            print(f"  @ 0x{addr:X}:")
            for a in arg_list:
                print(f"    arg{a['arg']} ({a['reg']}): {a['value']}  [{a['source']}]")
        print()


def _cmd_pseudo(args):
    adapter = _make_adapter(args.file)
    from ppm_engine.topology.callgraph import CallGraph
    from ppm_engine.reconstruct.pseudo import PseudoCodeGenerator

    cg = CallGraph.from_pe(adapter)

    try:
        rva = int(args.rva, 0)
    except ValueError:
        print(f"Error: invalid RVA '{args.rva}' (use hex like 0x78B8)")
        return

    # Build maps
    import_map = {addr: fn.import_name for addr, fn in cg.functions.items() if fn.is_import}
    string_map = {s["rva"]: s["value"] for s in adapter.strings(min_len=4)}

    # Disassemble
    import capstone
    text_sec = None
    for sec in adapter._pe.sections:
        if b".text" in sec.Name:
            text_sec = sec
            break
    if not text_sec:
        print("Error: no .text section")
        return

    text_data = text_sec.get_data()
    offset = rva - text_sec.VirtualAddress
    if offset < 0 or offset >= len(text_data):
        print(f"Error: RVA 0x{rva:X} outside .text section")
        return

    fn = cg.functions.get(rva)
    fn_size = min(fn.size if fn and fn.size else 0x400, 0x1000)

    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    insns = list(md.disasm(text_data[offset:offset + fn_size], rva))

    # Trim at ret
    trimmed = []
    for insn in insns:
        trimmed.append(insn)
        if insn.mnemonic in ("ret", "retn"):
            break

    gen = PseudoCodeGenerator()
    pseudo = gen.generate(rva, trimmed, import_map, string_map)
    print(pseudo)


def _cmd_risk(args):
    from ppm_engine.adapters.lnk import LNKAdapter
    lnk = LNKAdapter(args.file)
    summary = lnk.summary()
    risk = lnk.analyze_risk()

    if args.json:
        print(json.dumps({**summary, "risk": risk}, indent=2))
        return

    print(f"{os.path.basename(args.file)}:")
    print(f"  Target: {summary['target'] or '(empty)'}")
    if summary["arguments"]:
        print(f"  Args: {summary['arguments'][:100]}")
    if summary["working_dir"]:
        print(f"  WorkDir: {summary['working_dir']}")
    print(f"  Window: {summary['show_command']}")
    print(f"  Risk: {risk['classification']} ({risk['risk']})")
    for ind in risk["indicators"]:
        print(f"    -> {ind}")


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

def _make_adapter(path: str):
    """Create the appropriate adapter for the file format."""
    from ppm_engine.detect import detect
    info = detect(path)
    fmt = info.format

    if fmt.startswith("PE"):
        from ppm_engine.adapters.pe import PEAdapter
        return PEAdapter(path)
    elif fmt.startswith("ELF"):
        from ppm_engine.adapters.elf import ELFAdapter
        return ELFAdapter(path)
    elif fmt.startswith("MACHO"):
        from ppm_engine.adapters.macho import MachOAdapter
        return MachOAdapter(path)
    elif fmt == "LNK":
        from ppm_engine.adapters.lnk import LNKAdapter
        return LNKAdapter(path)
    else:
        print(f"Error: unsupported format '{fmt}' for {path}", file=sys.stderr)
        sys.exit(1)


def _print_tree(tree: dict, indent: int = 0):
    label = tree.get("label", "?")
    ntype = tree.get("type", "")
    etype = tree.get("edge_type", "")
    prefix = "  " * indent
    annotation = f" ({etype})" if etype and etype != "calls" else ""
    print(f"{prefix}{label} [{ntype}]{annotation}")
    for ch in tree.get("children", []):
        _print_tree(ch, indent + 1)


if __name__ == "__main__":
    main()
