#include "../../core/plugin/IPlugin.h"
#include "../../core/plugin/PluginRegistry.h"
#include "../../core/globals.h"
#include <cstdio>

// ── Stub commands ────────────────────────────────────────────────────────────

static void CmdHandles(int argc, char** argv) {
    (void)argc; (void)argv;
    printf("[handles] /handles — stub\n");
}

static void CmdHandleClose(int argc, char** argv) {
    (void)argc; (void)argv;
    printf("[handles] /handle-close — stub\n");
}

static void CmdHandleScan(int argc, char** argv) {
    (void)argc; (void)argv;
    printf("[handles] /handle-scan — stub\n");
}

static void CmdTimedelta(int argc, char** argv) {
    (void)argc; (void)argv;
    printf("[handles] /timedelta — stub\n");
}

static void CmdProcToken(int argc, char** argv) {
    (void)argc; (void)argv;
    printf("[handles] /proc-token — stub\n");
}

// ── Plugin registration ──────────────────────────────────────────────────────

class HandlesPlugin : public IPlugin {
public:
    const char* Name() const override { return "handles"; }
    const char* Description() const override { return "Handle enumeration, closing, and token inspection"; }
    std::vector<Command> Commands() override {
        return {
            {"handles",      "[drive]",           "Open file handles system-wide",                                "Handles", CmdHandles},
            {"handle-close", "<pid> <handle>",    "Close a handle (kernel walk for pid=4)",                       "Handles", CmdHandleClose},
            {"handle-scan",  "<pid> [opts]",      "Kernel HANDLE_TABLE scan (--access --target-pid --close --spin)", "Handles", CmdHandleScan},
            {"timedelta",    "<pid> [ms]",        "Monitor transient System handles (race window)",               "Handles", CmdTimedelta},
            {"proc-token",   "<pid>",             "Dump process token details",                                   "Handles", CmdProcToken},
        };
    }
};

PPM_PLUGIN(HandlesPlugin);
