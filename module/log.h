#pragma once

#include <cstdio>

#ifdef ENABLE_LOGGING

#include "hook/imports.h"

static void log_init() {
  imports::pAllocConsole();
  FILE* file = nullptr;
  freopen_s(&file, "CONOUT$", "w", stdout);
}

#define LOG(format, ...) printf(format "\n", ##__VA_ARGS__)

#else

static void log_init() {}
#define LOG(format, ...) ((void)0)

#endif
