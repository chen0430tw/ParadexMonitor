#include "PluginRegistry.h"
#include "../compat.h"
#include "../ansi.h"
#include <cstdio>
#include <cstring>
#include <algorithm>
#include <map>

// ── Static storage ───────────────────────────────────────────────────────────

static std::vector<IPlugin*>& plugins() {
    static std::vector<IPlugin*> v;
    return v;
}

static std::vector<Command>& commands() {
    static std::vector<Command> v;
    return v;
}

static bool s_built = false;

static void BuildIfNeeded() {
    if (s_built) return;
    s_built = true;
    commands().clear();
    for (auto* p : plugins()) {
        for (auto& c : p->Commands())
            commands().push_back(c);
    }
}

// ── Public API ───────────────────────────────────────────────────────────────

void PluginRegistry::Add(IPlugin* p) {
    plugins().push_back(p);
    s_built = false;   // force rebuild on next access
}

void PluginRegistry::InitAll() {
    for (auto* p : plugins()) p->Init();
}

void PluginRegistry::ShutdownAll() {
    for (auto* p : plugins()) p->Shutdown();
}

const Command* PluginRegistry::Find(const char* name) {
    BuildIfNeeded();
    for (auto& c : commands()) {
        if (ppm_stricmp(c.name, name) == 0) return &c;
    }
    return nullptr;
}

const std::vector<IPlugin*>& PluginRegistry::Plugins() { return plugins(); }

const std::vector<Command>& PluginRegistry::AllCommands() {
    BuildIfNeeded();
    return commands();
}

void PluginRegistry::PrintHelp(const char* prog) {
    BuildIfNeeded();

    // Group commands by their group field, preserving first-seen order
    std::vector<std::string> groupOrder;
    std::map<std::string, std::vector<const Command*>> grouped;

    for (auto& c : commands()) {
        std::string g = c.group ? c.group : "Other";
        if (grouped.find(g) == grouped.end())
            groupOrder.push_back(g);
        grouped[g].push_back(&c);
    }

    printf("Usage: %s [--json] [--quiet] [--debug] <command> [args]\n\n", prog);

    for (auto& g : groupOrder) {
        printf("  %s%s%s\n", A_BOLD, g.c_str(), A_RESET);
        for (auto* c : grouped[g]) {
            char left[48];
            if (c->args && c->args[0])
                snprintf(left, sizeof(left), "/%s %s", c->name, c->args);
            else
                snprintf(left, sizeof(left), "/%s", c->name);
            printf("    %-36s %s\n", left, c->brief);
        }
        printf("\n");
    }

    printf("  Per-command help:  %s /<command> --help\n", prog);
#ifdef _WIN32
    printf("  Backend: RTCore64.sys (BYOVD kernel R/W)\n");
#endif
    printf("\n");
}
