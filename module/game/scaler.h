#pragma once
#include "math.hpp"
#include "../hook/imports.h"
#include <Windows.h>
#include <cstdint>

inline constexpr float PLAYFIELD_WIDTH = 512.0f;
inline constexpr float PLAYFIELD_HEIGHT = 384.0f;
inline constexpr float REFERENCE_HEIGHT = 480.0f;
inline constexpr float VERT_POSITION_RATIO = 3.0f / 4.0f;
inline constexpr float PLAYFIELD_Y_NUDGE = -16.0f;

namespace scaler_detail {
  inline float g_ww = 0.0f;
  inline float g_wh = 0.0f;

  inline BOOL CALLBACK find_wnd(HWND hwnd, LPARAM) {
    if (!imports::pGetWindowThreadProcessId)
      return TRUE;
    DWORD pid;
    imports::pGetWindowThreadProcessId(hwnd, &pid);
    if (pid == imports::pGetCurrentProcessId() && imports::pIsWindowVisible(hwnd)) {
      RECT r;
      imports::pGetClientRect(hwnd, &r);
      int w = r.right - r.left, h = r.bottom - r.top;
      if (w > 200 && h > 200) {
        g_ww = static_cast<float>(w);
        g_wh = static_cast<float>(h);
        return FALSE;
      }
    }
    return TRUE;
  }
}  // namespace scaler_detail

inline void update_wnd() {
  if (imports::pEnumWindows)
    imports::pEnumWindows(scaler_detail::find_wnd, 0);
}

struct playfield_scaler {
  float window_width = 1920.0f;
  float window_height = 1080.0f;

  void update() {
    update_wnd();
    if (scaler_detail::g_ww > 0.0f) {
      window_width = scaler_detail::g_ww;
      window_height = scaler_detail::g_wh;
    }
  }

  float get_scale() const { return window_height / REFERENCE_HEIGHT; }

  vec2 to_screen(vec2 pos) const {
    float ratio = get_scale();

    float scaled_w = PLAYFIELD_WIDTH * ratio;
    float scaled_h = PLAYFIELD_HEIGHT * ratio;

    float off_x = (window_width - scaled_w) * 0.5f;
    float off_y = (window_height - scaled_h) * VERT_POSITION_RATIO + PLAYFIELD_Y_NUDGE * ratio;

    return {scaled_w * (pos.x / PLAYFIELD_WIDTH) + off_x,
            scaled_h * (pos.y / PLAYFIELD_HEIGHT) + off_y};
  }

  float scale_value(float v) const { return v * get_scale(); }
};

inline playfield_scaler g_scaler;
