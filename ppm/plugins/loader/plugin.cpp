#include "../../core/plugin/IPlugin.h"
#include "../../core/plugin/PluginRegistry.h"
#include "../../core/globals.h"
#include <cstdio>

// ── Stub commands ────────────────────────────────────────────────────────────

static void CmdMapDriver(int argc, char** argv) {
    (void)argc; (void)argv;
    printf("[loader] /map-driver — stub\n");
}

// ── Plugin registration ──────────────────────────────────────────────────────

class LoaderPlugin : public IPlugin {
public:
    const char* Name() const override { return "loader"; }
    const char* Description() const override { return "Unsigned driver mapping (DSE bypass)"; }
    std::vector<Command> Commands() override {
        return {
            {"map-driver", "<path.sys>", "Map unsigned driver into kernel (KDU-style DSE bypass)", "Loader", CmdMapDriver},
        };
    }
};

PPM_PLUGIN(LoaderPlugin);
