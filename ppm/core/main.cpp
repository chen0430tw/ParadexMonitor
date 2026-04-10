#include <cstdio>
#include <cstring>
#include "compat.h"
#include "globals.h"
#include "ansi.h"
#include "plugin/PluginRegistry.h"
#include "engine_ipc.h"

// ── Global state ─────────────────────────────────────────────────────────────
bool g_jsonMode    = false;
bool g_quiet       = false;
bool g_debug       = false;
bool g_ansiEnabled = false;

static EngineIPC g_engine;

// ── Banner ───────────────────────────────────────────────────────────────────
static void Banner() {
    printf(
        "\n"
        " %s____  ____  __  __ %s\n"
        " %s|  _ \\|  _ \\|  \\/  |%s  Paradex Process Monitor\n"
        " %s| |_) | |_) | |\\/| |%s  Binary reconstruction & kernel inspection\n"
        " %s|  __/|  __/| |  | |%s\n"
        " %s|_|   |_|   |_|  |_|%s  see what shouldn't be seen\n"
        "\n",
        A_CYAN, A_RESET,
        A_CYAN, A_RESET,
        A_CYAN, A_RESET,
        A_CYAN, A_RESET,
        A_CYAN, A_RESET
    );
}

// ── Flag stripping ───────────────────────────────────────────────────────────
static const char* StripPrefix(const char* a) {
    if (a[0] == '/' || a[0] == '-') { a++; if (a[0] == '-') a++; }
    // MSYS/Git Bash path expansion: /notify → /C:/Program Files/Git/notify
    const char* slash = strrchr(a, '/');
    if (!slash) slash = strrchr(a, '\\');
    if (slash) a = slash + 1;
    return a;
}

static bool IsGlobalFlag(const char* raw) {
    const char* f = StripPrefix(raw);
    return (ppm_stricmp(f, "json") == 0 ||
            ppm_stricmp(f, "quiet") == 0 ||
            ppm_stricmp(f, "debug") == 0);
}

// ── Main ─────────────────────────────────────────────────────────────────────
int main(int argc, char* argv[]) {
#ifdef _WIN32
    SetConsoleOutputCP(65001);
#endif
    setvbuf(stdout, nullptr, _IONBF, 0);

    // Pre-scan global flags
    for (int i = 1; i < argc; i++) {
        const char* f = StripPrefix(argv[i]);
        if (ppm_stricmp(f, "json")  == 0) g_jsonMode = true;
        if (ppm_stricmp(f, "quiet") == 0) g_quiet    = true;
        if (ppm_stricmp(f, "debug") == 0) g_debug    = true;
    }

    if (!g_jsonMode) AnsiInit();
    if (!g_quiet) Banner();

    // Find command: first arg that isn't a global flag
    const char* cmd = nullptr;
    int cmdIdx = -1;
    for (int i = 1; i < argc; i++) {
        if (IsGlobalFlag(argv[i])) continue;
        cmd = StripPrefix(argv[i]);
        cmdIdx = i;
        break;
    }

    if (!cmd || ppm_stricmp(cmd, "help") == 0 || ppm_stricmp(cmd, "h") == 0) {
        PluginRegistry::PrintHelp(argv[0]);
        return cmd ? 0 : 1;
    }

    // Initialize plugins
    PluginRegistry::InitAll();

    // Try to start analysis engine (non-fatal if unavailable)
    if (!g_engine.Start()) {
        DBG("Analysis engine not available (Python not found or ppm-engine not installed)\n");
    }

    // Dispatch command
    const Command* c = PluginRegistry::Find(cmd);
    if (!c) {
        fprintf(stderr, "[!] Unknown command: /%s\n", cmd);
        fprintf(stderr, "    Run with --help to see available commands.\n");
        PluginRegistry::ShutdownAll();
        return 1;
    }

    // Build sub-argc/argv for the command (skip global flags + command itself)
    int subArgc = 0;
    char* subArgv[256] = {};
    for (int i = cmdIdx + 1; i < argc && subArgc < 255; i++) {
        if (IsGlobalFlag(argv[i])) continue;
        subArgv[subArgc++] = argv[i];
    }

    c->exec(subArgc, subArgv);

    // Cleanup
    g_engine.Stop();
    PluginRegistry::ShutdownAll();
    return 0;
}
