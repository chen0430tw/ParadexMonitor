#include "../../core/plugin/IPlugin.h"
#include "../../core/plugin/PluginRegistry.h"
#include <cstdio>

static void CmdObcb(int argc, char** argv)           { (void)argc; (void)argv; printf("[callbacks] /obcb — stub\n"); }
static void CmdDisable(int argc, char** argv)         { (void)argc; (void)argv; printf("[callbacks] /disable — stub\n"); }
static void CmdEnable(int argc, char** argv)          { (void)argc; (void)argv; printf("[callbacks] /enable — stub\n"); }
static void CmdNotify(int argc, char** argv)          { (void)argc; (void)argv; printf("[callbacks] /notify — stub\n"); }
static void CmdNdisable(int argc, char** argv)        { (void)argc; (void)argv; printf("[callbacks] /ndisable — stub\n"); }
static void CmdNotifyRegistry(int argc, char** argv)  { (void)argc; (void)argv; printf("[callbacks] /notify-registry — stub\n"); }

class CallbacksPlugin : public IPlugin {
public:
    const char* Name() const override { return "callbacks"; }
    const char* Description() const override { return "ObCallback, Notify, CmCallback enumeration & control"; }
    std::vector<Command> Commands() override {
        return {
            {"obcb",             "[process|thread]",    "Enumerate ObRegisterCallbacks",              "Callbacks & Notify", CmdObcb},
            {"disable",          "<addr>",              "Disable ObCallback entry",                   "Callbacks & Notify", CmdDisable},
            {"enable",           "<addr>",              "Re-enable ObCallback entry",                 "Callbacks & Notify", CmdEnable},
            {"notify",           "[image|process|thread]", "Enumerate Ps*NotifyRoutine arrays",       "Callbacks & Notify", CmdNotify},
            {"ndisable",         "<fn_addr>",           "Zero EX_CALLBACK slot (unregister notify)",  "Callbacks & Notify", CmdNdisable},
            {"notify-registry",  "[--kill <drv>]",      "Enumerate/kill CmRegisterCallback routines", "Callbacks & Notify", CmdNotifyRegistry},
        };
    }
};

PPM_PLUGIN(CallbacksPlugin);
