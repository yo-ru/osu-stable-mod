#pragma once
#include "../hook/nocrt.h"

struct vec2 {
  float x, y;
  vec2 operator+(vec2 o) const { return {x + o.x, y + o.y}; }
  vec2 operator-(vec2 o) const { return {x - o.x, y - o.y}; }
  vec2 operator*(float s) const { return {x * s, y * s}; }
  float dot(vec2 o) const { return x * o.x + y * o.y; }
  float length() const { return nc_sqrtf(x * x + y * y); }
  float length_sq() const { return x * x + y * y; }

  vec2 normalized() const {
    float l = length();
    return l < 0.0001f ? vec2{0, 0} : vec2{x / l, y / l};
  }
};
