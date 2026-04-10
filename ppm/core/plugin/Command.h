#pragma once

// Describes a single CLI command registered by a plugin.
struct Command {
    const char* name;    // "proc", "obcb", "analyze", ...
    const char* args;    // "<pid> [all]" (shown in help)
    const char* brief;   // "List processes (kernel EPROCESS walk)"
    const char* group;   // "Recon" — auto-grouped in help output
    void (*exec)(int argc, char** argv);
};
