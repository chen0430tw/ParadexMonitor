#include "../../core/plugin/IPlugin.h"
#include "../../core/plugin/PluginRegistry.h"
#include "../../core/globals.h"
#include <cstdio>

// ── Stub commands ────────────────────────────────────────────────────────────

static void CmdWlmon(int argc, char** argv) {
    (void)argc; (void)argv;
    printf("[winlogon] /wlmon — stub\n");
}

static void CmdWlinject(int argc, char** argv) {
    (void)argc; (void)argv;
    printf("[winlogon] /wlinject — stub\n");
}

static void CmdWluninject(int argc, char** argv) {
    (void)argc; (void)argv;
    printf("[winlogon] /wluninject — stub\n");
}

static void CmdWluninjectAll(int argc, char** argv) {
    (void)argc; (void)argv;
    printf("[winlogon] /wluninject-all — stub\n");
}

static void CmdWlSas(int argc, char** argv) {
    (void)argc; (void)argv;
    printf("[winlogon] /wl-sas — stub\n");
}

static void CmdWlPersist(int argc, char** argv) {
    (void)argc; (void)argv;
    printf("[winlogon] /wl-persist — stub\n");
}

static void CmdWlUnpersist(int argc, char** argv) {
    (void)argc; (void)argv;
    printf("[winlogon] /wl-unpersist — stub\n");
}

static void CmdWnd(int argc, char** argv) {
    (void)argc; (void)argv;
    printf("[winlogon] /wnd — stub\n");
}

static void CmdWndClose(int argc, char** argv) {
    (void)argc; (void)argv;
    printf("[winlogon] /wnd-close — stub\n");
}

// ── Plugin registration ──────────────────────────────────────────────────────

class WinlogonPlugin : public IPlugin {
public:
    const char* Name() const override { return "winlogon"; }
    const char* Description() const override { return "Winlogon monitoring, DLL injection, window enumeration"; }
    std::vector<Command> Commands() override {
        return {
            {"wlmon",          "[ms]",                     "Monitor winlogon.exe state (continuous)",       "Winlogon & Desktop", CmdWlmon},
            {"wlinject",       "<dll>",                    "Inject DLL into winlogon (APC)",                "Winlogon & Desktop", CmdWlinject},
            {"wluninject",     "<dll>",                    "Unload DLL from winlogon",                      "Winlogon & Desktop", CmdWluninject},
            {"wluninject-all", "<dll> [--force]",          "Unload DLL from ALL processes",                 "Winlogon & Desktop", CmdWluninjectAll},
            {"wl-sas",         "",                         "Trigger Ctrl+Alt+Del (SAS)",                    "Winlogon & Desktop", CmdWlSas},
            {"wl-persist",     "<dll>",                    "Add DLL to AppInit_DLLs persistence",           "Winlogon & Desktop", CmdWlPersist},
            {"wl-unpersist",   "<dll>",                    "Remove DLL from AppInit_DLLs",                  "Winlogon & Desktop", CmdWlUnpersist},
            {"wnd",            "[--all] [--all-desktops]", "Enumerate windows across desktops",             "Winlogon & Desktop", CmdWnd},
            {"wnd-close",      "<hwnd>",                   "Dismiss window (WM_CLOSE / IDOK)",              "Winlogon & Desktop", CmdWndClose},
        };
    }
};

PPM_PLUGIN(WinlogonPlugin);
