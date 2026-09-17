#pragma once
// hashes byte patterns at compile time and scans memory without storing them verbatim

#include <Windows.h>
#include "../hook/nocrt.h"
#include "../hook/imports.h"

static constexpr unsigned int K_MAX_SIG_LEN = 64;
static constexpr unsigned int K_WC_WORDS = (K_MAX_SIG_LEN + 7) / 8;
static constexpr unsigned long long K_FNV_OFFSET = 0xcbf29ce484222325ULL;
static constexpr unsigned long long K_FNV_PRIME = 0x100000001b3ULL;

struct sig_pattern {
  unsigned long long hash;
  unsigned int length;
  unsigned char wildcards[K_WC_WORDS];
};

constexpr unsigned long long fnv1a_step(unsigned long long h, unsigned char b) {
  return (h ^ b) * K_FNV_PRIME;
}

constexpr unsigned char hex_nibble(char c) {
  if (c >= '0' && c <= '9')
    return (unsigned char)(c - '0');
  if (c >= 'a' && c <= 'f')
    return (unsigned char)(c - 'a' + 10);
  if (c >= 'A' && c <= 'F')
    return (unsigned char)(c - 'A' + 10);
  return 0;
}

// parse a pattern into its hash and wildcard mask
constexpr sig_pattern compile_pattern(const char* s) {
  sig_pattern p = {K_FNV_OFFSET, 0, {}};
  unsigned int idx = 0;
  while (*s != '\0' && idx < K_MAX_SIG_LEN) {
    if (*s == ' ' || *s == '\t') {
      ++s;
      continue;
    }
    if (*s == '?') {
      p.wildcards[idx / 8] = (unsigned char)(p.wildcards[idx / 8] | (1u << (idx % 8)));
      p.hash = fnv1a_step(p.hash, 0);
      ++s;
      if (*s == '?')
        ++s;
      ++idx;
      continue;
    }
    unsigned char hi = hex_nibble(*s);
    ++s;
    unsigned char lo = (*s && *s != ' ') ? hex_nibble(*s) : 0;
    if (*s && *s != ' ')
      ++s;
    unsigned char byte = (unsigned char)((hi << 4) | lo);
    p.hash = fnv1a_step(p.hash, byte);
    ++idx;
  }
  p.length = idx;
  return p;
}

static unsigned char* scan_region_hashed(unsigned char* base, unsigned int region_size,
                                         const sig_pattern* pat) {
  if (region_size < pat->length)
    return nullptr;
  __try {
    for (unsigned int i = 0; i + pat->length <= region_size; ++i) {
      unsigned long long h = K_FNV_OFFSET;
      for (unsigned int j = 0; j < pat->length; ++j) {
        bool wild = (pat->wildcards[j / 8] >> (j % 8)) & 1u;
        unsigned char b = wild ? (unsigned char)0 : base[i + j];
        h = fnv1a_step(h, b);
      }
      if (h == pat->hash)
        return base + i;
    }
  } __except (EXCEPTION_EXECUTE_HANDLER) {
  }
  return nullptr;
}

static unsigned char* scan_module_hashed(void* module_base, const sig_pattern* pat) {
  if (!module_base)
    return nullptr;
  auto* dos = (IMAGE_DOS_HEADER*)module_base;
  auto* nt = (IMAGE_NT_HEADERS32*)((char*)module_base + dos->e_lfanew);
  return scan_region_hashed((unsigned char*)module_base, nt->OptionalHeader.SizeOfImage, pat);
}

// cache memory regions to avoid repeated VirtualQuery walks
struct cached_scan_region {
  unsigned char* base;
  unsigned int size;
};

static constexpr int K_MAX_CACHED_REGIONS = 512;
inline cached_scan_region g_scan_rw_regions[K_MAX_CACHED_REGIONS];
inline cached_scan_region g_scan_rwx_regions[K_MAX_CACHED_REGIONS];
inline int g_scan_rw_count = 0;
inline int g_scan_rwx_count = 0;

static void refresh_scan_cache() {
  g_scan_rw_count = 0;
  g_scan_rwx_count = 0;

  MEMORY_BASIC_INFORMATION mbi;
  unsigned char* addr = nullptr;

  while (imports::pVirtualQuery(addr, &mbi, sizeof(mbi))) {
    if (mbi.State == MEM_COMMIT) {
      if (mbi.Protect == PAGE_READWRITE && mbi.Type == MEM_PRIVATE && mbi.RegionSize >= 0x1000 &&
          mbi.RegionSize < 0x200000 && g_scan_rw_count < K_MAX_CACHED_REGIONS) {
        g_scan_rw_regions[g_scan_rw_count++] = {(unsigned char*)mbi.BaseAddress,
                                                (unsigned int)mbi.RegionSize};
      }
      if (mbi.Protect == PAGE_EXECUTE_READWRITE && mbi.RegionSize < 0x200000 &&
          g_scan_rwx_count < K_MAX_CACHED_REGIONS) {
        g_scan_rwx_regions[g_scan_rwx_count++] = {(unsigned char*)mbi.BaseAddress,
                                                  (unsigned int)mbi.RegionSize};
      }
    }
    addr = (unsigned char*)mbi.BaseAddress + mbi.RegionSize;
    if (addr < (unsigned char*)mbi.BaseAddress)
      break;
  }
}

// scan private read-write regions used by the CLR heap
static unsigned char* scan_rw(const sig_pattern* pat) {
  for (int i = 0; i < g_scan_rw_count; ++i) {
    __try {
      MEMORY_BASIC_INFORMATION verify;
      if (imports::pVirtualQuery(g_scan_rw_regions[i].base, &verify, sizeof(verify)) &&
          verify.State == MEM_COMMIT && verify.Protect == PAGE_READWRITE) {
        auto* hit = scan_region_hashed(g_scan_rw_regions[i].base, g_scan_rw_regions[i].size, pat);
        if (hit)
          return hit;
      }
    } __except (1) {
      imports::pSleep(0);
    }
    // let the CLR move objects between scans
    if ((i + 1) % 16 == 0)
      imports::pSleep(0);
  }
  return nullptr;
}

// scan executable regions used by JIT code
static unsigned char* scan_rwx(const sig_pattern* pat) {
  for (int i = 0; i < g_scan_rwx_count; ++i) {
    __try {
      auto* hit = scan_region_hashed(g_scan_rwx_regions[i].base, g_scan_rwx_regions[i].size, pat);
      if (hit)
        return hit;
    } __except (1) {
    }
  }
  return nullptr;
}
