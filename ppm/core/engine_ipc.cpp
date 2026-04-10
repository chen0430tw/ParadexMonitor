#include "engine_ipc.h"
#include "globals.h"
#include <cstdio>
#include <cstring>

// ── Stub implementation ──────────────────────────────────────────────────────
// Full pipe-based IPC will be implemented in Phase 2.
// For now, provides the interface so the rest of the code compiles.

bool EngineIPC::Start(const char* python_cmd, const char* engine_dir) {
    (void)python_cmd; (void)engine_dir;
    DBG("EngineIPC::Start() — stub, engine not launched\n");
    return false;
}

void EngineIPC::Stop() {
    DBG("EngineIPC::Stop() — stub\n");
}

bool EngineIPC::IsRunning() const {
    return false;
}

std::string EngineIPC::Call(const std::string& jsonRequest, int timeoutMs) {
    (void)jsonRequest; (void)timeoutMs;
    return R"({"error":"engine not started"})";
}

std::string EngineIPC::Analyze(const char* filePath) {
    char buf[4096];
    snprintf(buf, sizeof(buf), R"({"command":"analyze","path":"%s"})", filePath);
    return Call(buf);
}

std::string EngineIPC::DepQuery(const char* filePath, const char* query) {
    char buf[4096];
    snprintf(buf, sizeof(buf),
        R"({"command":"depgraph","path":"%s","query":"%s"})", filePath, query);
    return Call(buf);
}
