#include "../../core/plugin/IPlugin.h"
#include "../../core/plugin/PluginRegistry.h"
#include <cstdio>
#include <cstring>

static void CmdAnalyze(int argc, char** argv) {
    if (argc < 1) {
        printf("Usage: /analyze <binary_path>\n");
        return;
    }
    printf("[inspect] /analyze %s — stub (will call ppm-engine)\n", argv[0]);
    // TODO: g_engine.Analyze(argv[0])
}

static void CmdDepgraph(int argc, char** argv) {
    if (argc < 1) {
        printf("Usage: /depgraph <binary_path> [--query <expr>]\n");
        return;
    }
    const char* query = nullptr;
    for (int i = 1; i < argc - 1; i++) {
        if (strcmp(argv[i], "--query") == 0) { query = argv[i+1]; break; }
    }
    printf("[inspect] /depgraph %s", argv[0]);
    if (query) printf(" --query \"%s\"", query);
    printf(" — stub\n");
}

static void CmdDisasm(int argc, char** argv) {
    (void)argc; (void)argv;
    printf("[inspect] /disasm — stub (capstone kernel VA disassembly)\n");
}

static void CmdDt(int argc, char** argv) {
    (void)argc; (void)argv;
    printf("[inspect] /dt — stub (kernel structure expansion)\n");
}

class InspectPlugin : public IPlugin {
public:
    const char* Name() const override { return "inspect"; }
    const char* Description() const override { return "Binary analysis, dependency graph, disassembly"; }
    std::vector<Command> Commands() override {
        return {
            {"analyze",   "<binary>",                    "Auto-analyze binary (detect, unpack, reconstruct)", "Analysis", CmdAnalyze},
            {"depgraph",  "<binary> [--query <expr>]",   "Dependency graph with queries",                     "Analysis", CmdDepgraph},
            {"disasm",    "<addr> [count]",              "Disassemble kernel VA (capstone)",                  "Analysis", CmdDisasm},
            {"dt",        "<struct> [addr]",             "Kernel structure field expansion",                  "Analysis", CmdDt},
        };
    }
};

PPM_PLUGIN(InspectPlugin);
