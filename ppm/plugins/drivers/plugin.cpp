#include "../../core/plugin/IPlugin.h"
#include "../../core/plugin/PluginRegistry.h"
#include "../../core/globals.h"
#include <cstdio>

// ── Stub commands ────────────────────────────────────────────────────────────

static void CmdDrvLoad(int argc, char** argv) {
    (void)argc; (void)argv;
    printf("[drivers] /drv-load — stub\n");
}

static void CmdDrvUnload(int argc, char** argv) {
    (void)argc; (void)argv;
    printf("[drivers] /drv-unload — stub\n");
}

static void CmdForceStop(int argc, char** argv) {
    (void)argc; (void)argv;
    printf("[drivers] /force-stop — stub\n");
}

static void CmdDrvZombie(int argc, char** argv) {
    (void)argc; (void)argv;
    printf("[drivers] /drv-zombie — stub\n");
}

static void CmdFlt(int argc, char** argv) {
    (void)argc; (void)argv;
    printf("[drivers] /flt — stub\n");
}

static void CmdFltDetach(int argc, char** argv) {
    (void)argc; (void)argv;
    printf("[drivers] /flt-detach — stub\n");
}

static void CmdUnmount(int argc, char** argv) {
    (void)argc; (void)argv;
    printf("[drivers] /unmount — stub\n");
}

static void CmdObjdir(int argc, char** argv) {
    (void)argc; (void)argv;
    printf("[drivers] /objdir — stub\n");
}

// ── Plugin registration ──────────────────────────────────────────────────────

class DriversPlugin : public IPlugin {
public:
    const char* Name() const override { return "drivers"; }
    const char* Description() const override { return "Driver loading/unloading, minifilters, object directories"; }
    std::vector<Command> Commands() override {
        return {
            {"drv-load",    "<path.sys>",               "Load kernel driver (NtLoadDriver)",           "Drivers & Minifilters", CmdDrvLoad},
            {"drv-unload",  "<name> <drvobj_va>",       "Force-unload (patch DriverUnload + sc stop)", "Drivers & Minifilters", CmdDrvUnload},
            {"force-stop",  "<name>",                   "NtUnloadDriver (bypass SCM error 1052)",      "Drivers & Minifilters", CmdForceStop},
            {"drv-zombie",  "<drvobj_va>",              "Diagnose zombie driver refcount",             "Drivers & Minifilters", CmdDrvZombie},
            {"flt",         "[drive]",                  "Minifilter instances (kernel walk)",           "Drivers & Minifilters", CmdFlt},
            {"flt-detach",  "<filter> <drive>",         "Force-detach mandatory minifilter",            "Drivers & Minifilters", CmdFltDetach},
            {"unmount",     "<drive>",                  "Force dismount + eject volume",               "Drivers & Minifilters", CmdUnmount},
            {"objdir",      "[path] [--kva <addr>]",    "Object directory walk",                       "Drivers & Minifilters", CmdObjdir},
        };
    }
};

PPM_PLUGIN(DriversPlugin);
