add_library(hook SHARED
  dllmain.cpp
  aim/aim_assist.cpp
  relax/relax.cpp
)
set_target_properties(hook PROPERTIES OUTPUT_NAME "DiscordHook")
target_include_directories(hook PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_precompile_headers(hook PRIVATE pch.h)
target_compile_options(hook PRIVATE /Zc:preprocessor /EHa /GR- /fp:fast /Oy)
target_link_options(hook PRIVATE /SAFESEH:NO)
target_compile_definitions(hook PRIVATE _HAS_EXCEPTIONS=0)
