cmake_minimum_required(VERSION 3.16)
project(ParadexMonitor VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ── Sources ───────────────────────────────────────────────────────────────────

set(CORE_SOURCES
    ppm/core/main.cpp
    ppm/core/engine_ipc.cpp
    ppm/core/plugin/PluginRegistry.cpp
)

set(PLUGIN_SOURCES
    ppm/plugins/recon/plugin.cpp
    ppm/plugins/callbacks/plugin.cpp
    ppm/plugins/inspect/plugin.cpp
    # Add new plugins here — one line per plugin
)

# ── Target ────────────────────────────────────────────────────────────────────

add_executable(ppm ${CORE_SOURCES} ${PLUGIN_SOURCES})

target_include_directories(ppm PRIVATE ppm)

# ── Platform-specific ─────────────────────────────────────────────────────────

if(WIN32)
    # Future: add driver backends, kernel utilities
    # target_sources(ppm PRIVATE ppm/core/driver/RTCore64Backend.cpp ...)
    # target_link_libraries(ppm PRIVATE psapi)
endif()

# ── Install ───────────────────────────────────────────────────────────────────

install(TARGETS ppm DESTINATION bin)
