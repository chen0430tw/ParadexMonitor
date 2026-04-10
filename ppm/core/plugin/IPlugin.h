#pragma once
#include "Command.h"
#include <vector>

// Base interface for all PPM plugins.
// Each plugin registers a set of commands under a group name.
class IPlugin {
public:
    virtual ~IPlugin() = default;
    virtual const char* Name() const = 0;             // "recon", "callbacks", ...
    virtual const char* Description() const = 0;      // one-line summary
    virtual std::vector<Command> Commands() = 0;      // all commands this plugin provides
    virtual void Init() {}                            // called after driver/engine ready
    virtual void Shutdown() {}                        // called before exit
};
