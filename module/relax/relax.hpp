#pragma once

#include <Windows.h>
#include <cstdint>

#include "../game/math.hpp"

namespace relax {

  // only edit values inside this namespace
  namespace config {
    inline bool enabled = true;

    // controls the generated timing and tapping profile
    // keep this unchanged for the same profile between launches
    // change any byte from 0x00 to 0xFF to create a different profile
    inline uint8_t seed[32] = {
        0xA7, 0x19, 0xD2, 0x43, 0x6E, 0xB8, 0x05, 0xF1,
        0x3C, 0x94, 0x7A, 0x20, 0xCD, 0x58, 0xE6, 0x11,
        0x82, 0x4F, 0xB3, 0x69, 0x0D, 0xD7, 0x35, 0xAE,
        0x51, 0xC4, 0x78, 0x16, 0xEB, 0x2A, 0x90, 0x5D,
    };

    // starts adding accuracy loss above this stream speed in BPM
    // 0 disables the speed limit and 180 starts accuracy loss above 180 BPM
    inline uint16_t bpm_limit = 0;
  }

  // osu! keybinds are detected automatically with Z and X used as fallbacks
  void initialize();
  void update(void* player, int audio_time, vec2 cursor_pos);
  void reset();

}  // namespace relax
