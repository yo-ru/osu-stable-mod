#pragma once
// small inline math, memory, and hashing helpers used by the hook
// keeps the hook independent from CRT startup code, imports, and global runtime state
// uses direct compiler and x86 instructions for predictable behavior in aim assist and relax
// covers only the input ranges used by the hook rather than every CRT edge case

#include <intrin.h>

// scalar math helpers compile directly into each caller
__forceinline float nc_fabsf(float x) {
  unsigned int i = *(unsigned int*)&x;
  i &= 0x7FFFFFFF;
  return *(float*)&i;
}

__forceinline float nc_floorf(float x) {
  float t = (float)(int)x;
  return t > x ? t - 1.0f : t;
}

__forceinline float nc_fminf(float a, float b) {
  return a < b ? a : b;
}
__forceinline float nc_fmaxf(float a, float b) {
  return a > b ? a : b;
}

__forceinline float nc_sqrtf(float x) {
  return _mm_cvtss_f32(_mm_sqrt_ss(_mm_set_ss(x)));
}

__forceinline float nc_clampf(float x, float lo, float hi) {
  return nc_fminf(nc_fmaxf(x, lo), hi);
}

// x87 and SSE instructions provide the transcendental math used by movement timing
__forceinline float nc_sinf(float x) {
  float _res;
  __asm {
    fld x
    fsin
    fstp _res
  }
  return _res;
}

__forceinline float nc_cosf(float x) {
  float _res;
  __asm {
    fld x
    fcos
    fstp _res
  }
  return _res;
}

__forceinline float nc_expf(float x) {
  if (x < -87.0f)
    return 0.0f;
  if (x > 87.0f)
    return 1e38f;
  float _res;
  __asm {
    fld x
    fldl2e
    fmulp st(1), st
    fld st(0)
    frndint
    fsub st(1), st
    fxch st(1)
    f2xm1
    fld1
    faddp st(1), st
    fscale
    fstp st(1)
    fstp _res
  }
  return _res;
}

__forceinline float nc_logf(float x) {
  if (x <= 0.0f)
    return -1e38f;
  float _res;
  __asm {
    fld1
    fld x
    fyl2x
    fldln2
    fmulp st(1), st
    fstp _res
  }
  return _res;
}

__forceinline float nc_tanhf(float x) {
  if (x > 10.0f)
    return 1.0f;
  if (x < -10.0f)
    return -1.0f;
  float e2x = nc_expf(2.0f * x);
  return (e2x - 1.0f) / (e2x + 1.0f);
}

// compiler intrinsics avoid external memory function calls
__forceinline void nc_memset(void* dst, int val, unsigned int size) {
  __stosb((unsigned char*)dst, (unsigned char)val, size);
}

__forceinline void nc_memcpy(void* dst, const void* src, unsigned int size) {
  __movsb((unsigned char*)dst, (const unsigned char*)src, size);
}

__forceinline int nc_memcmp(const void* a, const void* b, unsigned int size) {
  const unsigned char* pa = (const unsigned char*)a;
  const unsigned char* pb = (const unsigned char*)b;
  for (unsigned int i = 0; i < size; i++) {
    if (pa[i] != pb[i])
      return pa[i] - pb[i];
  }
  return 0;
}

// allocation-free FNV-1a hashes support narrow and wide names
__forceinline unsigned int nc_hash(const char* str) {
  unsigned int h = 0x811c9dc5;
  while (*str) {
    h ^= (unsigned char)*str++;
    h *= 0x01000193;
  }
  return h;
}

__forceinline unsigned int nc_hashw(const wchar_t* str) {
  unsigned int h = 0x811c9dc5;
  while (*str) {
    h ^= (unsigned char)(*str & 0xFF);
    h *= 0x01000193;
    h ^= (unsigned char)((*str >> 8) & 0xFF);
    h *= 0x01000193;
    str++;
  }
  return h;
}

__forceinline unsigned int nc_hashw_ci(const wchar_t* str) {
  unsigned int h = 0x811c9dc5;
  while (*str) {
    wchar_t c = *str;
    if (c >= L'A' && c <= L'Z')
      c += 32;
    h ^= (unsigned char)(c & 0xFF);
    h *= 0x01000193;
    h ^= (unsigned char)((c >> 8) & 0xFF);
    h *= 0x01000193;
    str++;
  }
  return h;
}
