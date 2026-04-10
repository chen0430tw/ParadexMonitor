#pragma once

// Cross-platform compatibility shims
#include <cstring>

#ifdef _WIN32
  // MSVC / Windows SDK provides _stricmp
  #define ppm_stricmp _stricmp
#else
  // GCC / Clang / POSIX
  #include <strings.h>
  #define ppm_stricmp strcasecmp
#endif
