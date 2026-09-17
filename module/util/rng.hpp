#pragma once
#include <cstdint>
#include "../hook/nocrt.h"

struct xorshift32 {
  uint32_t state = 0;

  void seed(uint32_t s) {
    state = s;
    if (!state)
      state = 0x9E3779B9u;
  }

  uint32_t next() {
    if (!state)
      seed((uint32_t)__rdtsc());
    state ^= state << 13;
    state ^= state >> 17;
    state ^= state << 5;
    return state;
  }

  float uniform_unit() { return (float)next() / 4294967296.0f; }

  float uniform_neg1_1() { return (float)next() / 2147483648.0f - 1.0f; }

  // box muller gaussian with the second value cached
  float gauss() {
    if (has_cached) {
      has_cached = false;
      return cached;
    }

    float u, v, s;
    do {
      u = uniform_neg1_1();
      v = uniform_neg1_1();
      s = u * u + v * v;
    } while (s >= 1.0f || s == 0.0f);

    float m = nc_sqrtf(-2.0f * nc_logf(s) / s);
    cached = v * m;
    has_cached = true;
    return u * m;
  }

 private:
  float cached = 0.0f;
  bool has_cached = false;
};
