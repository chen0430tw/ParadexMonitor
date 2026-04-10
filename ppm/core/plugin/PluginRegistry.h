#pragma once
#include "IPlugin.h"
#include <vector>
#include <string>

// Central registry for all plugins and their commands.
// Plugins register via PPM_PLUGIN() macro at static-init time.
class PluginRegistry {
public:
    // Register a plugin (called at static init)
    static void Add(IPlugin* p);

    // Lifecycle
    static void InitAll();
    static void ShutdownAll();

    // Lookup
    static const Command* Find(const char* name);
    static const std::vector<IPlugin*>& Plugins();
    static const std::vector<Command>&  AllCommands();

    // Help output — auto-grouped by Command::group
    static void PrintHelp(const char* prog);
};

// Macro: place in a plugin .cpp to auto-register at static init
#define PPM_PLUGIN(cls) \
    static cls s_instance_##cls; \
    namespace { struct _reg_##cls { \
        _reg_##cls() { PluginRegistry::Add(&s_instance_##cls); } \
    } _autoreg_##cls; }
