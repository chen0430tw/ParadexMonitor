# Paradex Process Monitor - Technical Whitepaper

> **Version**: 0.1 Draft
> **Date**: 2026-04-10
> **Status**: Architecture Planning

---

## 1. What is Paradex Process Monitor

Paradex Process Monitor (PPM) is a binary analysis and kernel inspection platform that **automatically reconstructs source-level architecture from compiled binaries**.

It is not a hex editor. It is not a debugger. It is a tool that takes any `.sys`, `.exe`, `.dll`, `.ko`, or `.so` file and answers questions like:

- "What callbacks does this driver register?"
- "Where does this evil handle come from?"
- "What is the complete attack chain from DriverEntry to TerminateProcess?"
- "Is this binary packed? With what? What's underneath?"

The name pays tribute to Sysinternals Process Monitor (ProcMon) by Mark Russinovich, and to Paradox Interactive's philosophy of deep systemic simulation. **Paradex** = Paradox + Explorer: seeing kernel internals through methods that shouldn't exist (BYOVD).

---

## 2. Origin

PPM fuses six existing projects:

| Project | Role in PPM | What it contributes |
|---------|------------|---------------------|
| **ObMaster** | Shell & kernel ops | 56 commands, BYOVD backend (RTCore64), CLI framework, ANSI/JSON output |
| **Tensorearch** | Analysis brain | Topology simulation, bottleneck detection, propagation chains, high-dimensional projection for pattern separation |
| **KDU** | Driver loader | 20+ BYOVD provider drivers, DSE bypass, kernel mapper |
| **WinObjEx64** | Object inspector | Object directory enumeration, kernel object header/type/SD parsing |
| **WinDbg** (concepts) | Struct/symbol engine | Structure field expansion (dt), PDB symbol resolution, disassembly |
| **bin2h** | Build tool | Embed driver binaries into C headers at compile time |

---

## 3. Core Principle: Topology-Driven Reconstruction

Traditional reverse engineering is bottom-up: read hex, guess instructions, manually trace call chains. PPM inverts this.

PPM borrows Tensorearch's core insight: **any structured system, when projected into a high-dimensional topological space, reveals its architecture as geometric invariants**. Tensorearch does this for neural network weight matrices; PPM does it for compiled binaries.

### 3.1 How it works

```
Input: ksafecenter64.sys (52 KB, PE64 driver)

Step 1 — Detect & Unpack
  Format: PE64 kernel driver
  Packing: none (entropy 5.2, normal)
  IAT: 47 imports from ntoskrnl.exe

Step 2 — Build topology
  Parse IAT → 47 ImportNodes
  Disassemble .text → 38 FunctionNodes
  Scan for call/jmp → 127 Calls edges
  Scan for LEA [rip+] → 23 References to globals
  Scan for string refs → 14 StringNodes

Step 3 — Pattern matching
  ObRegisterCallbacks(0x75C6) → registers PreOp(0x78B8)  [ObCallback pattern]
  CmRegisterCallbackEx(0x7A47) → registers CmCb(0x7C20)  [CmCallback pattern]
  PsSetLoadImageNotifyRoutine(0x...) → registers notify    [Notify pattern]

Step 4 — Propagation
  DriverEntry → ObRegisterCallbacks → PreOp
    PreOp → PsGetProcessId → IsProtectedPid
      IsProtectedPid → ObOpenObjectByPointer(0x200) × 2
      IsProtectedPid → string match against whitelist
    PreOp → AND DesiredAccess (strip bits)
  DriverEntry → CmRegisterCallbackEx → CmCb
    CmCb → CmCallbackGetKeyObjectID → RtlCompareUnicodeString
    CmCb → return STATUS_ACCESS_DENIED for blacklisted keys

Step 5 — Reconstruct
  Output: complete architecture diagram + pseudo-code + attack chain
  Time: < 5 seconds
```

Compare: manual analysis of the same binary took 90+ minutes during the April 10, 2026 session.

### 3.2 Topology for unpacking

Packing/encryption adds a transformation layer on top of real code. In topological space:

- **Pack envelope**: low-dimensional, linear, repetitive (XOR loops, decompress stubs)
- **Real payload**: high-dimensional, branching, structured (function prologues, API calls)

These two geometries are separable without knowing the packer. This is the `topo_strip` algorithm — it works on unknown/custom packers where signature-based tools fail.

---

## 4. Architecture

### 4.1 Two-process design

```
┌──────────────────────────────────────────┐
│  ppm (C++ single binary)                 │
│                                          │
│  ┌──────────┐  ┌───────────────────┐     │
│  │ Dear ImGui│  │ CLI (--json)      │     │
│  │ GUI       │  │ Agent-friendly    │     │
│  └─────┬─────┘  └────────┬──────────┘     │
│        │                 │                │
│        └────────┬────────┘                │
│                 │                         │
│  ┌──────────────▼──────────────────┐      │
│  │ Plugin system                   │      │
│  │ (ObMaster commands, all 56)     │      │
│  └──────────────┬──────────────────┘      │
│                 │                         │
│  ┌──────────────▼──────────────────┐      │
│  │ Kernel ops (Windows only)       │      │
│  │ BYOVD: RTCore64 / KDU multi    │      │
│  └─────────────────────────────────┘      │
└────────────────┬─────────────────────────┘
                 │ JSON over stdin/stdout
                 │ (subprocess)
┌────────────────▼─────────────────────────┐
│  ppm-engine (Python)                     │
│                                          │
│  detect → unpack → topology → propagate  │
│    → depgraph → reconstruct → output     │
│                                          │
│  Optional bridges:                       │
│    QCU (quantum collapse for ambiguity)  │
│    URP (distributed graph scheduling)    │
│    exMs (ELF syscall emulation)          │
│    HCE (unified orchestration)           │
└──────────────────────────────────────────┘
```

### 4.2 Why two processes

| Concern | Decision |
|---------|----------|
| Language fit | C++ for kernel R/W + GUI; Python for analysis (capstone, pefile, LIEF, numpy ecosystem) |
| Cross-platform | C++ GUI compiles on Windows + Linux; Python engine runs anywhere; kernel ops `#ifdef _WIN32` |
| Agent-friendly | JSON stdin/stdout is the native IPC — AI agents call either side directly |
| Isolation | Engine crash doesn't kill GUI; GUI crash doesn't lose analysis state |
| Deployment | Single exe (ppm) + pip install ppm-engine; or bundled with PyInstaller |

### 4.3 Mode switching

```
ppm                          → GUI mode (Dear ImGui window)
ppm --cli                    → Interactive CLI (like ObMaster today)
ppm --json analyze foo.sys   → Single-shot JSON output (Agent mode)
ppm --serve 8080             → HTTP API (future, for web UI)
```

No flag = GUI. Has `--json` = Agent. Has `--cli` = terminal. Automatic.

---

## 5. Plugin System

### 5.1 Interface

```cpp
// ppm/core/plugin/IPlugin.h
class IPlugin {
public:
    virtual const char* Name() = 0;            // "recon"
    virtual const char* Group() = 0;           // "Recon" (help page heading)
    virtual std::vector<Command> Commands() = 0;
    virtual void Init() {}     // called after driver ready
    virtual void Shutdown() {} // called before exit
};

struct Command {
    const char* name;    // "proc"
    const char* args;    // "[pid]"
    const char* brief;   // "List processes"
    void (*exec)(int argc, char** argv);
};

// Registration macro
#define PPM_PLUGIN(cls) \
    static cls s_##cls; \
    static auto _reg_##cls = PluginRegistry::Add(&s_##cls)
```

### 5.2 Adding a new command

One file, one registration:

```cpp
// plugins/recon/whoami.cpp
#include "core/plugin/IPlugin.h"

static void CmdWhoami(int, char**) {
    printf("Current token: ...\n");
}

// In ReconPlugin::Commands(), add one line:
{"whoami", "", "Show current security context", CmdWhoami},
```

Help page auto-generates from registered commands. No need to edit main.cpp.

### 5.3 Plugin list (initial, migrated from ObMaster)

| Plugin | Commands | Source |
|--------|----------|--------|
| recon | proc, drivers, services, net, dll-list, inj-scan, epdump | ObMaster |
| callbacks | obcb, disable, enable, obcb-install, notify, ndisable, notify-registry | ObMaster |
| handles | handles, handle-close, handle-scan, timedelta, proc-token | ObMaster |
| drivers | drv-load, drv-unload, force-stop, drv-zombie, flt, flt-detach, unmount, objdir | ObMaster |
| memory | memscan, memrestore, watchfix, safepatch, restore, guard-*, patch, pte, rd64, wr64, ptebase | ObMaster |
| elevation | runas, elevate-self, elevate-pid, enable-priv, kill, make-ppl, kill-ppl | ObMaster |
| winlogon | wlmon, wlinject, wluninject, wluninject-all, wl-sas, wl-persist, wl-unpersist, wnd, wnd-close | ObMaster |
| loader | map-driver (KDU-style DSE bypass mapper) | New |
| inspect | objex, dt, disasm, sym | New |

### 5.4 Future plugin slots (reserved)

| Plugin | Purpose | When |
|--------|---------|------|
| `network` | Packet capture, protocol decode | When needed |
| `filesystem` | NTFS MFT walk, alternate data streams | When needed |
| `registry` | Hive parsing, key monitoring | When needed |
| `hypervisor` | VT-x/EPT inspection | When needed |

---

## 6. Analysis Engine

### 6.1 Pipeline

```
detect → unpack → adapt → topology → propagate → depgraph → reconstruct
  │         │        │        │           │           │           │
  ▼         ▼        ▼        ▼           ▼           ▼           ▼
format    strip    unified   call      entry→cb    queryable   pseudo-
 type     packer   node      graph     →handle     graph +     code +
          layer    graph     + data    chain       JSON API    arch
                             flow                              diagram
```

Each stage is independent. You can call `depgraph` directly if you already have a topology. You can call `unpack` without running the full pipeline.

### 6.2 Detect (format auto-detection)

```python
MZ          → PE32 / PE64 / PE driver / .NET
\x7fELF     → ELF exec / ELF shared / ELF relocatable / kernel module
\xfe\xed... → Mach-O
\xCA\xFE... → Mach-O fat binary
otherwise   → raw shellcode (capstone linear sweep)
```

Sub-classification for PE drivers:
- Has `DriverEntry` export or INIT section → kernel driver
- Imports `ntoskrnl.exe` → kernel driver
- Imports `kernel32.dll` only → userland exe

### 6.3 Unpack

```
Known packers:
  UPX         → upx -d (or manual section rebuild)
  VMProtect   → handler table extraction (partial)
  Themida     → emulation-based OEP finding
  ASPack      → section table fixup

Unknown packers:
  Entropy scan → locate encrypted regions
  XOR crack   → frequency analysis / known-plaintext (MZ header, PE signature)
  Emulate     → unicorn runs unpack stub, dump at VirtualProtect(PAGE_EXECUTE)
  Topo strip  → high-dimensional projection separates envelope from payload

Multi-layer:
  UPX(XOR(real_code)) → xor_crack first, then upx decompress
  Pipeline auto-chains: if output still looks packed, run again
```

### 6.4 Topology

```python
# From disassembly, build:
CallGraph:
  nodes = functions (identified by prologue scan + call targets)
  edges = direct calls, indirect calls (call [rip+X] → IAT resolve)

DataFlow:
  track register values through basic blocks
  identify: which arg to API X came from where
  e.g.: ObOpenObjectByPointer(rcx=EPROCESS, edx=0x200, ...)
        → edx=0x200 is DesiredAccess, means PROCESS_QUERY_INFORMATION

CouplingMatrix:
  for each function pair (A, B):
    coupling = shared globals + call frequency + data dependency
  cluster tightly-coupled functions → "modules"
```

### 6.5 Dependency Graph

The depgraph is the central queryable data structure:

```python
class DepGraph:
    nodes: list[Node]    # Function, Import, Callback, Global, String
    edges: list[Edge]    # Calls, Registers, References, PassesArg

    # Queries
    def who_registers(callback_type: str) -> list[Chain]
    def what_calls(func: str) -> list[Node]
    def trace_from(entry: str, depth: int) -> Tree
    def find_path(src: str, dst: str) -> list[Node]
    def find_sinks(api_name: str) -> list[Chain]
    def impact_of(func: str) -> ImpactReport
    def diff(other: DepGraph) -> DiffReport

    # Output
    def to_json() -> dict       # Agent consumption
    def to_dot() -> str         # Graphviz
    def to_imgui() -> dict      # GUI node positions
    def to_ascii() -> str       # Terminal tree
```

### 6.6 Reconstruct

Two levels:

**Function-level pseudo-code** (capstone → lifted IR → C-like output):
```c
// Auto-generated from 0x1400078B8
void PreOp(void* ctx, OB_PRE_OPERATION_INFO* info) {
    if (info->Operation != OB_OPERATION_HANDLE_CREATE) return;
    if (KeGetCurrentIrql() >= DISPATCH_LEVEL) return;
    HANDLE pid = PsGetProcessId(info->Object);
    if (info->Parameters->DesiredAccess & 1) {
        if (IsProtectedPid(pid)) {
            info->Parameters->DesiredAccess &= 0xFFFFFFFE;
        }
    }
}
```

**Architecture-level summary** (pattern matching → natural language):
```
ksafecenter64.sys — YunGengXin process protection driver

Callbacks:
  - ObCallback PreOp: strips PROCESS_TERMINATE from handles to protected PIDs
  - CmCallback: blocks registry writes to \SOFTWARE\kSafeCenter
  - LoadImage notify: monitors DLL loading into protected processes

Protection mechanism:
  - Maintains internal PID whitelist (checked via image name comparison)
  - PIDs younger than 50 seconds are exempt (startup grace period)
  - System process (PID ≤ 4) is always exempt

Self-protection:
  - DriverUnload = NULL (cannot be unloaded via SCM)
  - DKOM: unlinks from PsLoadedModuleList (hides from EnumDeviceDrivers)
  - DeviceObject reference kept alive (prevents garbage collection)
```

---

## 7. GUI

### 7.1 Technology

- **Dear ImGui** + GLFW + OpenGL 3.3
- Cross-platform: Windows (MSVC), Linux (GCC/Clang)
- Single window, tabbed layout

### 7.2 Tabs

| Tab | Content |
|-----|---------|
| **Analysis** | Drop binary here → auto-analyze → architecture diagram + pseudo-code |
| **Topology** | Interactive node graph (drag, zoom, click node → details panel) |
| **Dependencies** | Dependency graph with query bar ("who_registers ObCallback") |
| **Terminal** | Embedded CLI (type ObMaster commands directly) |
| **Kernel** | Live kernel state: processes, callbacks, handles, drivers (Windows only) |
| **Hex** | Hex view with highlighted regions (packed/code/data/strings) — auxiliary, not primary |

### 7.3 Topology view

Node types have distinct colors:
```
Blue    = Function
Green   = Import (API call)
Red     = Callback (registered handler)
Yellow  = Global variable
Purple  = String constant
Orange  = Syscall / IOCTL
```

Edge types:
```
Solid   = direct call
Dashed  = indirect call (function pointer)
Dotted  = data reference (LEA, MOV from global)
Bold    = registers (callback registration)
```

Click a node → right panel shows:
- Disassembly
- Pseudo-code
- Cross-references (who calls me, who do I call)
- If callback: what triggers it, what it does

---

## 8. Agent Interface

PPM is designed to be called by AI agents (Claude, GPT, etc.) as a tool.

### 8.1 Protocol

```bash
# Analyze a binary
ppm --json analyze <path>

# Query dependency graph
ppm --json depgraph <path> --query "find_sinks ObOpenObjectByPointer"

# Kernel inspection (Windows, needs driver)
ppm --json proc
ppm --json obcb
ppm --json notify registry

# All output is JSON, parseable by any agent
```

### 8.2 JSON schema (analyze output)

```json
{
  "file": "ksafecenter64.sys",
  "format": "PE64_DRIVER",
  "size": 53248,
  "packed": false,
  "entry_point": "0x140017000 → 0x140001458",
  "imports": {"ntoskrnl.exe": ["ObRegisterCallbacks", "CmRegisterCallbackEx", "..."]},
  "functions": 38,
  "strings": ["\\SOFTWARE\\kSafeCenter", "\\Registry\\Machine\\System\\CurrentControlSet"],
  "callbacks": [
    {"type": "ObCallback", "register_site": "0x75C6", "handler": "0x78B8", "behavior": "handle_strip"},
    {"type": "CmCallback", "register_site": "0x7A47", "handler": "0x7C20", "behavior": "registry_block"}
  ],
  "attack_chain": ["DriverEntry → ObRegisterCallbacks(PreOp) → PsGetProcessId → IsProtectedPid → strip access"],
  "pseudo_code": {"0x78B8": "void PreOp(...) { ... }"},
  "architecture_summary": "Process protection driver. Strips handle access to whitelisted PIDs. Blocks registry writes to own config keys."
}
```

### 8.3 Agent workflow

```
Agent: "Analyze ksafecenter64.sys and tell me if it creates evil handles"

1. Agent calls: ppm --json analyze ksafecenter64.sys
2. Agent reads JSON → sees ObOpenObjectByPointer calls with access=0x200
3. Agent calls: ppm --json depgraph ksafecenter64.sys --query "find_sinks ObOpenObjectByPointer"
4. Agent reads chains → both use 0x200 (QUERY_INFO), not 0x1FFFFF (ALL_ACCESS)
5. Agent concludes: "This driver does NOT create PROCESS_ALL_ACCESS handles"

Total time: < 10 seconds
Manual equivalent: 90+ minutes (April 10 2026 session)
```

---

## 9. External System Bridges

All bridges are **optional**. PPM works standalone; bridges add capabilities when available.

| Bridge | System | When to use | Fallback without it |
|--------|--------|-------------|---------------------|
| `qcu_bridge` | QCU (treesea) | Ambiguous OEP / path selection → quantum collapse picks best candidate | Heuristic scoring (entropy + API density) |
| `urp_bridge` | URP/URX Runtime | Distributed multi-binary batch analysis across nodes | Local thread pool (`std::thread` / `multiprocessing`) |
| `exms_bridge` | exMs | Linux ELF binary analysis with syscall emulation | Unicorn emulation (slower, less accurate) |
| `hce_bridge` | HCE (treesea) | Unified orchestration when QCU + URP + Tree Diagram all active | Direct bridge calls |

Bridge detection is automatic:
```python
class BridgeManager:
    def detect(self):
        if can_import("qcu.runtime.runner"):  self.qcu = QCUBridge()
        if tcp_reachable(config.urp_host):     self.urp = URPBridge()
        if path_exists(config.exms_runtime):   self.exms = ExMsBridge()
```

---

## 10. Build System

### 10.1 C++ (CMake)

```cmake
cmake_minimum_required(VERSION 3.20)
project(ParadexMonitor LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 17)

# Core
add_executable(ppm
    ppm/core/main.cpp
    ppm/core/cli.cpp
    ppm/core/engine_ipc.cpp
    ppm/gui/app.cpp
    ppm/gui/main_window.cpp
    # ... all plugin .cpp files
)

# Dear ImGui (vendored)
add_subdirectory(vendor/imgui)
target_link_libraries(ppm PRIVATE imgui glfw OpenGL::GL)

# Windows-only kernel ops
if(WIN32)
    target_sources(ppm PRIVATE
        ppm/core/driver/RTCore64Backend.cpp
        ppm/core/kutil/kutil.cpp
        ppm/core/kutil/pte.cpp
    )
    target_link_libraries(ppm PRIVATE psapi ntdll)
endif()
```

### 10.2 Python (pyproject.toml)

```toml
[project]
name = "ppm-engine"
version = "0.1.0"
requires-python = ">=3.10"
dependencies = [
    "capstone>=5.0",
    "pefile>=2023.2",
    "lief>=0.14",
    "unicorn>=2.0",
    "numpy>=1.24",
]

[project.scripts]
ppm-engine = "ppm_engine.__main__:main"
```

### 10.3 Cross-platform matrix

| Component | Windows | Linux |
|-----------|---------|-------|
| ppm (GUI) | MSVC + CMake | GCC/Clang + CMake |
| ppm (kernel ops) | Full (BYOVD) | Stub (no kernel R/W) |
| ppm-engine | Full | Full |
| Dear ImGui | GLFW + OpenGL | GLFW + OpenGL |

Linux build omits kernel plugins; analysis engine works identically.

---

## 11. Development Phases

### Phase 1: Foundation
- [ ] CMakeLists.txt + build on Windows
- [ ] Plugin system (IPlugin, Command, PluginRegistry)
- [ ] Migrate ObMaster commands as plugins (no behavioral change)
- [ ] Help auto-generation from plugin registry
- [ ] Basic Dear ImGui shell (Terminal tab only)

### Phase 2: Engine
- [ ] ppm-engine skeleton (__main__.py JSON service loop)
- [ ] C++ ↔ Python IPC (engine_ipc.cpp)
- [ ] detect.py (PE/ELF auto-detection)
- [ ] adapters/pe.py (pefile + LIEF)
- [ ] topology/callgraph.py (capstone-based call graph)
- [ ] depgraph core (nodes, edges, basic queries)

### Phase 3: Analysis
- [ ] Pattern library (ObCallback, CmCallback, APC inject, DKOM, handle strip)
- [ ] propagation/chain.py (entry → callback → API chain tracing)
- [ ] reconstruct/pseudo.py (disasm → pseudo-code lifting)
- [ ] reconstruct/architecture.py (full binary summary)
- [ ] Validate against known samples: ksafecenter64, kshutdown64, kboot64

### Phase 4: Unpack
- [ ] entropy.py (sliding window entropy map)
- [ ] xor_crack.py (single/multi-byte XOR, rolling XOR)
- [ ] encoding.py (Base64, ROT, custom alphabet)
- [ ] emulate.py (unicorn-based OEP finder)
- [ ] topo_strip.py (topology-based packer separation)
- [ ] UPX, VMProtect, Themida handlers

### Phase 5: GUI
- [ ] Analysis tab (drop file → results)
- [ ] Topology view (interactive node graph)
- [ ] Dependencies tab (query bar + graph)
- [ ] Kernel tab (live process/callback/handle view)
- [ ] Cross-platform Linux build

### Phase 6: Bridges
- [ ] QCU bridge (ambiguity resolution)
- [ ] URP bridge (distributed batch analysis)
- [ ] exMs bridge (ELF syscall emulation)
- [ ] HCE bridge (unified orchestration)

---

## 12. File Inventory

```
D:\ParadexMonitor\
├── CMakeLists.txt
├── README.md
│
├── ppm/                              C++ main binary
│   ├── core/
│   │   ├── main.cpp                  Entry (GUI / CLI / Agent auto-switch)
│   │   ├── cli.h / cli.cpp           Command registry, flag parsing, help gen
│   │   ├── engine_ipc.h / cpp        Python subprocess JSON pipe
│   │   ├── output.h / cpp            Unified output (text / json / csv)
│   │   ├── globals.h                 Global flags + driver pointer
│   │   ├── ansi.h                    ANSI color macros
│   │   ├── jutil.h                   JSON output helpers
│   │   ├── driver/
│   │   │   ├── IDriverBackend.h      Abstract kernel R/W interface
│   │   │   ├── RTCore64Backend.cpp   MSI Afterburner backend
│   │   │   └── KDUBackend.cpp        Multi-provider KDU backend
│   │   ├── kutil/
│   │   │   ├── kutil.h / cpp         Kernel utilities
│   │   │   ├── pte.h / cpp           Page table operations
│   │   │   ├── symbols.h / cpp       PDB symbol resolver
│   │   │   └── structs.h / cpp       Kernel struct definitions
│   │   ├── plugin/
│   │   │   ├── IPlugin.h             Plugin interface
│   │   │   ├── PluginRegistry.h/cpp  Discovery + registration
│   │   │   └── Command.h             Command descriptor
│   │   └── bridges/
│   │       ├── bridge_manager.h/cpp  Auto-detect available bridges
│   │       ├── urp_client.h/cpp      URP TCP direct client
│   │       └── bridge_config.h       Connection settings
│   │
│   ├── gui/
│   │   ├── app.h / cpp               GLFW + OpenGL init
│   │   ├── main_window.h / cpp       Tab framework
│   │   ├── tab_analysis.h / cpp      Binary analysis results
│   │   ├── tab_topology.h / cpp      Interactive node graph
│   │   ├── tab_deps.h / cpp          Dependency graph + query
│   │   ├── tab_terminal.h / cpp      Embedded CLI
│   │   ├── tab_kernel.h / cpp        Live kernel state (Windows)
│   │   ├── topology_view.h / cpp     Node/edge renderer
│   │   └── hex_view.h / cpp          Hex viewer (auxiliary)
│   │
│   └── plugins/
│       ├── recon/        (proc, drivers, services, net, dll-list, inj-scan, epdump)
│       ├── callbacks/    (obcb, disable, enable, notify, ndisable, notify-registry)
│       ├── handles/      (handles, handle-close, handle-scan, timedelta, proc-token)
│       ├── drivers/      (drv-load, drv-unload, force-stop, drv-zombie, flt, objdir)
│       ├── memory/       (memscan, memrestore, watchfix, safepatch, guard, pte, rd64)
│       ├── elevation/    (runas, elevate-self, elevate-pid, kill, make-ppl)
│       ├── winlogon/     (wlmon, wlinject, wluninject, wl-sas, wnd)
│       ├── loader/       (map-driver — KDU DSE bypass)
│       └── inspect/      (objex, dt, disasm, sym)
│
├── engine/
│   ├── pyproject.toml
│   └── ppm_engine/
│       ├── __init__.py
│       ├── __main__.py               JSON stdin/stdout service loop
│       ├── detect.py                 Format auto-detection
│       ├── adapters/
│       │   ├── __init__.py
│       │   ├── pe.py                 PE32/PE64 parsing
│       │   ├── elf.py                ELF parsing
│       │   └── macho.py              Mach-O parsing
│       ├── unpack/
│       │   ├── __init__.py
│       │   ├── detect.py             Packer identification
│       │   ├── entropy.py            Sliding window entropy
│       │   ├── xor_crack.py          XOR/multi-byte auto-crack
│       │   ├── encoding.py           Base64/ROT/custom decode
│       │   ├── emulate.py            Unicorn OEP finder
│       │   ├── topo_strip.py         Topology-based separation
│       │   ├── upx.py                UPX handler
│       │   ├── vmprotect.py          VMP handler extraction
│       │   └── themida.py            Themida framework
│       ├── topology/
│       │   ├── __init__.py
│       │   ├── callgraph.py          Call graph construction
│       │   ├── coupling.py           Module coupling analysis
│       │   └── dataflow.py           Data flow tracking
│       ├── propagation/
│       │   ├── __init__.py
│       │   └── chain.py              Entry → callback → API chain
│       ├── depgraph/
│       │   ├── __init__.py
│       │   ├── build.py              Graph builder
│       │   ├── nodes.py              Node types
│       │   ├── edges.py              Edge types
│       │   ├── query.py              Graph query API
│       │   ├── render.py             JSON/DOT/ImGui/ASCII output
│       │   └── diff.py               Binary-to-binary diff
│       ├── reconstruct/
│       │   ├── __init__.py
│       │   ├── pseudo.py             Pseudo-code generation
│       │   └── architecture.py       Architecture summary
│       ├── patterns/
│       │   ├── __init__.py
│       │   ├── base.py               Pattern base class
│       │   ├── ob_callback.py        ObRegisterCallbacks pattern
│       │   ├── cm_callback.py        CmRegisterCallback pattern
│       │   ├── apc_inject.py         APC injection pattern
│       │   ├── dkom.py               DKOM hiding pattern
│       │   └── handle_strip.py       Handle access stripping
│       ├── bridges/
│       │   ├── __init__.py
│       │   ├── base.py               IBridge interface
│       │   ├── qcu_bridge.py         QCU quantum collapse
│       │   ├── urp_bridge.py         URP distributed scheduling
│       │   ├── exms_bridge.py        exMs ELF emulation
│       │   └── hce_bridge.py         HCE orchestration
│       └── tests/
│
├── tools/
│   ├── bin2h.py                      Binary → C header
│   └── gen_patterns.py               Pattern signature generator
│
├── tests/
│   ├── samples/                      Known binaries for validation
│   └── test_pipeline.py              End-to-end tests
│
└── docs/
    ├── whitepaper.md                 This document
    ├── architecture.md               Detailed architecture
    ├── plugin_api.md                 Plugin development guide
    ├── engine_protocol.md            C++ ↔ Python JSON protocol
    └── bridge_protocol.md            External system integration
```

---

*Paradex Process Monitor — see what shouldn't be seen.*
