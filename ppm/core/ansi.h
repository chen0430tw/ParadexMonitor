#pragma once
#include "globals.h"

// ANSI color — runtime ternary so they work as printf args
#define A_RESET   (g_ansiEnabled ? "\033[0m"  : "")
#define A_BOLD    (g_ansiEnabled ? "\033[1m"  : "")
#define A_DIM     (g_ansiEnabled ? "\033[2m"  : "")
#define A_RED     (g_ansiEnabled ? "\033[91m" : "")
#define A_GREEN   (g_ansiEnabled ? "\033[92m" : "")
#define A_YELLOW  (g_ansiEnabled ? "\033[93m" : "")
#define A_BLUE    (g_ansiEnabled ? "\033[94m" : "")
#define A_CYAN    (g_ansiEnabled ? "\033[96m" : "")

#ifdef _WIN32
#include <Windows.h>
inline void AnsiInit() {
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD mode = 0;
    if (h != INVALID_HANDLE_VALUE && GetConsoleMode(h, &mode)) {
        SetConsoleMode(h, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
        g_ansiEnabled = true;
    }
}
#else
#include <cstdlib>
inline void AnsiInit() {
    const char* term = getenv("TERM");
    g_ansiEnabled = (term && term[0] != '\0');
}
#endif
