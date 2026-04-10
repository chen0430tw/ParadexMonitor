# Paradex Process Monitor

Binary reconstruction & kernel inspection platform.

PPM takes any compiled binary (.sys, .exe, .dll, .ko, .so) and automatically
reconstructs its architecture: what callbacks it registers, what APIs it calls,
what attack chains it implements — in seconds, not hours.

## Quick Start

### Build (C++)
```bash
cmake -B build -G Ninja
cmake --build build
```

### Install Engine (Python)
```bash
cd engine
pip install -e .
```

### Usage
```bash
# GUI mode (Dear ImGui — coming soon)
./ppm

# CLI mode
./ppm --quiet /analyze path/to/driver.sys

# Agent mode (JSON output)
./ppm --json analyze driver.sys

# Kernel inspection (Windows, needs RTCore64)
./ppm /proc
./ppm /obcb
./ppm /notify registry
```

### Python Engine (standalone)
```bash
echo '{"command":"ping"}' | python -m ppm_engine
echo '{"command":"detect","path":"driver.sys"}' | python -m ppm_engine
echo '{"command":"analyze","path":"driver.sys"}' | python -m ppm_engine
```

## Architecture

Two-process design: C++ GUI/CLI + Python analysis engine, connected via JSON pipe.

- **ppm** (C++): Dear ImGui GUI, CLI framework, plugin system, kernel ops (BYOVD)
- **ppm-engine** (Python): Binary analysis — detect, unpack, topology, depgraph, reconstruct

## Plugin System

Add a new command in 3 lines:
```cpp
// In any plugin's Commands() method:
{"my-cmd", "<args>", "Description", "Group", CmdMyCmd},
```

## Analysis Pipeline

```
detect → unpack → adapt → topology → depgraph → patterns → reconstruct
```

## External Bridges (Optional)

| Bridge | System | Purpose |
|--------|--------|---------|
| QCU | treesea/qcu | Quantum collapse for ambiguity resolution |
| URP | URX Runtime | Distributed analysis scheduling |
| exMs | exMs | ELF syscall emulation |
| HCE | treesea/hce | Unified orchestration |

## License

MIT
