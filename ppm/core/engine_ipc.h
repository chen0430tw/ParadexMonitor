#pragma once
#include <string>

// IPC with the Python analysis engine (ppm-engine).
// Launches as subprocess, communicates via JSON over stdin/stdout.
class EngineIPC {
public:
    // Start the Python engine subprocess.
    // python_cmd: "python3" or full path; engine_dir: path to ppm_engine package.
    bool Start(const char* python_cmd = "python3", const char* engine_dir = nullptr);
    void Stop();
    bool IsRunning() const;

    // Send a JSON request, receive a JSON response.
    // Blocks until response arrives or timeout (ms, 0 = no timeout).
    std::string Call(const std::string& jsonRequest, int timeoutMs = 30000);

    // Convenience: analyze a binary file
    std::string Analyze(const char* filePath);

    // Convenience: query dependency graph
    std::string DepQuery(const char* filePath, const char* query);

private:
#ifdef _WIN32
    void* m_hProcess = nullptr;  // HANDLE
    void* m_hStdinWr = nullptr;  // write end of child stdin
    void* m_hStdoutRd = nullptr; // read end of child stdout
#else
    int m_pid = -1;
    int m_stdinFd = -1;
    int m_stdoutFd = -1;
#endif
};
