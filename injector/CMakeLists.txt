add_executable(injector entry.cpp shellcode.cpp)
set_target_properties(injector PROPERTIES
  OUTPUT_NAME "DiscordSetup"
  MSVC_RUNTIME_LIBRARY "MultiThreaded"
)
target_compile_options(injector PRIVATE /Zc:preprocessor)
target_compile_definitions(injector PRIVATE DISABLE_OUTPUT)
target_link_libraries(injector PRIVATE shell32)
set_source_files_properties(shellcode.cpp PROPERTIES COMPILE_OPTIONS "/GS-")
