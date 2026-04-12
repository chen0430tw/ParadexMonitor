# Paradex Process Monitor

Binary reconstruction & kernel inspection platform.

PPM takes any compiled binary (.sys, .exe, .dll, .ocx, .ko, .so, .dylib, .lnk) or installer package (NSIS, MSI, Inno Setup, InstallShield, Setup Factory, 7z SFX, ISO, PyInstaller, MSIX) and automatically reconstructs its architecture: what callbacks it registers, what APIs it calls, what attack chains it implements -- in seconds, not hours.

## Supported Formats

| Format | Adapter | Capabilities |
|--------|---------|-------------|
| **PE** (exe/dll/sys/ocx) | `PEAdapter` | IAT, imports, strings, callgraph, patterns, chains |
| **ELF** (Linux binaries/ko) | `ELFAdapter` | PLT calls, imports, strings, kernel module detection |
| **Mach-O** (macOS/iOS) | `MachOAdapter` | dyld bindings, stub resolution (ARM64+x64), indirect symbol table |
| **LNK** (Windows shortcuts) | `LNKAdapter` | Target/args extraction, LOLBin/Base64/hidden window risk assessment |
| **NSIS** (Nullsoft installer) | `nsis` adapter | LZMA/Zlib/Bzip2 decompression, string table extraction with variable expansion ($INSTDIR, $TEMP, shell folders), 87-opcode script bytecode decoding, pattern/chain topology analysis |
| **MSI** (Windows Installer) | `msi` adapter | OLE2 parsing, CustomAction/File/Registry/Property table extraction |
| **Inno Setup** | `inno` adapter | Signature detection, LZMA decompression, string extraction |
| **Setup Factory** | `sfactory` adapter | Via sfextract library (CybercentreCanada) |
| **InstallShield** | `ishield` adapter | Pure Python port of unshield core (V5 file_table + V6 linear descriptor) |
| **7z SFX** | `sfx7z` adapter | 7z magic detection after PE stub, py7zr file listing |
| **ISO** (ISO 9660/UDF) | `iso` adapter | pycdlib directory tree, suspicious executable flagging |
| **PyInstaller** | `pyinst` adapter | MEI/TOC parsing, entry scripts + module + binary extraction |
| **MSIX/AppX** | `msix` adapter | ZIP + AppxManifest.xml capabilities/permissions |
| **Media/docs** | detect only | JPEG, PNG, WAV, PDF, ZIP, MP4, TEXT, and 12 more |

Non-binary formats (images, audio, text) are correctly identified and rejected -- no crashes on unexpected input.

## Quick Start

### Install Engine (Python)
```bash
cd engine
pip install -e .
# Optional: pip install lief  (for ELF/Mach-O support)
```

### Usage
```bash
# Analyze a binary (JSON output)
echo '{"command":"analyze","path":"driver.sys"}' | python -m ppm_engine

# Detect format only
echo '{"command":"detect","path":"unknown.bin"}' | python -m ppm_engine

# Query dependency graph
echo '{"command":"depgraph","path":"driver.sys","query":"who_registers ObCallback"}' | python -m ppm_engine

# Ping (check engine status)
echo '{"command":"ping"}' | python -m ppm_engine
```

### C++ CLI (coming soon)
```bash
cmake -B build -G Ninja
cmake --build build

./ppm --json analyze driver.sys    # Agent mode
./ppm --quiet /analyze driver.sys  # CLI mode
./ppm                              # GUI mode (Dear ImGui)
```

## Analysis Pipeline

```
detect --> unpack --> adapt --> callgraph --> depgraph --> patterns --> chains --> reconstruct
  |          |         |          |             |            |           |            |
format    packer     unified    call         queryable    ob_cb      entry->cb    pseudo-code
 type     detect     adapter    graph        graph +      cm_cb      ->handle     + arch
                    (PE/ELF/   + data       JSON API     apc_inj    chain        summary
                     MachO)     flow                     dkom
                                                         handle
```

### Pattern Detection

| Pattern | What it detects | Confidence |
|---------|----------------|------------|
| `ob_callback` | ObRegisterCallbacks handler registration | 0.75-0.9 |
| `cm_callback` | CmRegisterCallbackEx registry callback | 0.7-0.85 |
| `apc_inject` | APC injection chain (notify+process+memory+APC) | 0.4-0.9 |
| `dkom` | Direct Kernel Object Manipulation (PsLoadedModuleList, ActiveProcessLinks) | 0.3-0.8 |
| `handle_strip` | Handle access bit stripping (AND mask pattern) | 0.7-0.85 |
| `xor_payload` | XOR-encoded payload/config data | 0.5-0.9 |
| **NSIS-specific:** | | |
| `service_control` | advapi32 ControlService/OpenService calls | 0.9 |
| `service_delete` | advapi32 DeleteService | 0.9 |
| `process_kill` | TerminateProcess / TerminProc | 0.85 |
| `pnp_remove` | devcon remove / PnP device removal | 0.95 |
| `driver_file_op` | .sys file manipulation (delete/copy) | 0.7 |
| `dll_injection_artifact` | Suspicious DLL references (kshut, inject) | 0.8 |

### depgraph Queries

```python
graph.who_registers("ObCallback")    # Type aliases: ObCallback, CmCallback, notify, minifilter
graph.who_registers("callback")      # Substring match across all callback types
graph.find_sinks("ZwTerminateProcess")  # All paths from entry to dangerous API
graph.trace_from("func_0x1458")      # BFS tree from any node
graph.impact_of("func_0x78B8")       # What breaks if this function is patched
graph.find_path("func_A", "func_B")  # Shortest path between two nodes
```

## Architecture

Two-process design: C++ GUI/CLI + Python analysis engine, connected via JSON over stdin/stdout.

```
ppm (C++)                          ppm-engine (Python)
  Plugin system (9 plugins)          detect, unpack, topology
  Dear ImGui GUI                     depgraph, patterns, chains
  Kernel ops (BYOVD)                 reconstruct, bridges
  CLI + --json agent mode            LNK risk assessment
```

### Input Hardening

All user-supplied paths are sanitized before processing:
- Protocol injection blocked (http/ldap/jndi/file)
- UNC paths blocked
- Windows reserved device names blocked (CON/NUL/PRN -- prevents open() hang)
- Unicode direction overrides stripped
- Null bytes stripped
- Non-binary formats safely rejected

Tested with 37 chaos/injection inputs: zero crashes.

## Testing

### Test Driver
`tests/samples/rk64.sys` -- synthetic 5KB driver that triggers all detection patterns:
- 4 patterns: ob_callback(0.9), cm_callback(0.85), apc_inject(0.8), dkom(0.5)
- 36 chains, 5 callbacks, 4 self-protection mechanisms
- DKOM strings, anti-analysis process targets, handle stripping

### Stress Test Results
470 system drivers from `C:\Windows\System32\drivers`:
- 0 errors, 0 crashes
- Largest: RTKVHD64.sys (6.3MB), most functions: Netwtw10.sys (9,141)
- False positive rates: apc_inject 0.8%, dkom 0.6%

## External Bridges (Optional)

| Bridge | System | Purpose |
|--------|--------|---------|
| QCU | treesea/qcu | Quantum collapse for ambiguity resolution |
| URP | URX Runtime | Distributed analysis scheduling |
| exMs | exMs | ELF syscall emulation |
| HCE | treesea/hce | Unified orchestration |

## License

MIT
