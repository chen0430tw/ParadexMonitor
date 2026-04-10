#include "../../core/plugin/IPlugin.h"
#include "../../core/plugin/PluginRegistry.h"
#include "../../core/globals.h"
#include <cstdio>

// ── Stub commands (will be migrated from ObMaster) ───────────────────────────

static void CmdProc(int argc, char** argv) {
    (void)argc; (void)argv;
    printf("[recon] /proc — stub (migrate from ObMaster cmd_proc.cpp)\n");
}

static void CmdDrivers(int argc, char** argv) {
    (void)argc; (void)argv;
    printf("[recon] /drivers — stub (migrate from ObMaster cmd_drivers.cpp)\n");
}

static void CmdServices(int argc, char** argv) {
    (void)argc; (void)argv;
    printf("[recon] /services — stub\n");
}

static void CmdNet(int argc, char** argv) {
    (void)argc; (void)argv;
    printf("[recon] /net — stub\n");
}

static void CmdDllList(int argc, char** argv) {
    (void)argc; (void)argv;
    printf("[recon] /dll-list — stub\n");
}

static void CmdInjScan(int argc, char** argv) {
    (void)argc; (void)argv;
    printf("[recon] /inj-scan — stub\n");
}

static void CmdEpdump(int argc, char** argv) {
    (void)argc; (void)argv;
    printf("[recon] /epdump — stub\n");
}

// ── Plugin registration ──────────────────────────────────────────────────────

class ReconPlugin : public IPlugin {
public:
    const char* Name() const override { return "recon"; }
    const char* Description() const override { return "Process, driver, service, DLL enumeration"; }
    std::vector<Command> Commands() override {
        return {
            {"proc",      "",            "List processes (kernel EPROCESS walk)",              "Recon", CmdProc},
            {"drivers",   "",            "Loaded kernel modules",                             "Recon", CmdDrivers},
            {"services",  "[all]",       "Windows services (default: running)",               "Recon", CmdServices},
            {"net",       "",            "TCP/UDP connections + owning process",              "Recon", CmdNet},
            {"dll-list",  "<name>",      "Find processes with <name> DLL loaded",             "Recon", CmdDllList},
            {"inj-scan",  "[pid]",       "Injection artifact scan (reflective, shellcode)",   "Recon", CmdInjScan},
            {"epdump",    "<pid>",       "Raw EPROCESS field dump",                          "Recon", CmdEpdump},
        };
    }
};

PPM_PLUGIN(ReconPlugin);
