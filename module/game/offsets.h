#pragma once
// field offsets for the current osu! stable build

// player
static constexpr int OFF_PLAYER_HIT_OBJECT_MANAGER = 0x044;
static constexpr int OFF_PLAYER_ASYNC_LOAD_COMPLETE = 0x180;
static constexpr int OFF_PLAYER_IS_REPLAY = 0x177;

// hit object manager
static constexpr int OFF_HOM_HIT_OBJECT_RADIUS = 0x018;
static constexpr int OFF_HOM_PREEMPT = 0x01C;
static constexpr int OFF_HOM_HIT_WINDOW_50 = 0x020;
static constexpr int OFF_HOM_HIT_WINDOW_100 = 0x024;
static constexpr int OFF_HOM_HIT_WINDOW_300 = 0x028;
static constexpr int OFF_HOM_HIT_OBJECTS = 0x048;

// hit object
static constexpr int OFF_HO_START_TIME = 0x010;
static constexpr int OFF_HO_END_TIME = 0x014;
static constexpr int OFF_HO_TYPE = 0x018;
static constexpr int OFF_HO_POSITION = 0x038;

// .NET List<T> / array internals
static constexpr int OFF_LIST_ITEMS = 0x04;
static constexpr int OFF_LIST_SIZE = 0x0C;
static constexpr int OFF_ARRAY_DATA = 0x08;

static constexpr int HIT_CIRCLE = 1;
static constexpr int HIT_SLIDER = 2;
static constexpr int HIT_SPINNER = 8;
