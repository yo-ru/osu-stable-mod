# osu! stable module

aim assist and relax for osu! stable

## requirements

- windows
- visual studio 2022 with the desktop c++ workload
- cmake 3.20 or newer
- ninja

## build

build the 32-bit release from the repository root

run these commands from the x86 native tools command prompt for visual studio 2022

```powershell
cmake --preset release
cmake --build build/release
```

the compiled files are placed in `build/release/bin`

- `DiscordHook.dll`
- `DiscordSetup.exe`

keep both files in the same directory

## use

1. run `DiscordSetup.exe`
2. start osu!
3. wait for the injector to finish

the injector loads `DiscordHook.dll` by default

## configuration

aim assist settings are in `module/aim/aim_assist.hpp`

relax settings are in `module/relax/relax.hpp`

rebuild after changing either file

relax reads the configured osu! left and right keys automatically and falls back to `Z` and `X`
