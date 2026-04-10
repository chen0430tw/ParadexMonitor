#pragma once

// Global flags — set by main() before command dispatch
extern bool g_jsonMode;     // --json: machine-readable JSON output
extern bool g_quiet;        // --quiet: suppress banner
extern bool g_debug;        // --debug: verbose diagnostics
extern bool g_ansiEnabled;  // true when VT processing active on stdout

#define DBG(...) do { if (g_debug) { printf("  [dbg] " __VA_ARGS__); } } while(0)
