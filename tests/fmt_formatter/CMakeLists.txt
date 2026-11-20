# fmt's CMakeLists.txt unconditionally sets the VERSION/SOVERSION/DEBUG_POSTFIX
# properties on its (always-configured) INTERFACE_LIBRARY "fmt-header-only" target;
# CMake rejected those properties on INTERFACE_LIBRARY targets before CMake 3.19
if (${CMAKE_VERSION} VERSION_GREATER_EQUAL "3.19.0")
  # The recipe runs its executable after linking, so nested cross-builds need
  # the parent system and emulator settings as well as the compiler.
  set(FMT_CROSSCOMPILING_ARGS)
  if(CMAKE_CROSSCOMPILING)
    string(REPLACE ";" "\\;" FMT_CROSSCOMPILING_EMULATOR "${CMAKE_CROSSCOMPILING_EMULATOR}")
    list(APPEND FMT_CROSSCOMPILING_ARGS
      "-DCMAKE_SYSTEM_NAME=${CMAKE_SYSTEM_NAME}"
      "-DCMAKE_CROSSCOMPILING_EMULATOR=${FMT_CROSSCOMPILING_EMULATOR}"
    )
  endif()
  add_test(NAME fmt_formatter_configure
    COMMAND ${CMAKE_COMMAND}
    -G "${CMAKE_GENERATOR}"
    -DCMAKE_CXX_COMPILER=${CMAKE_CXX_COMPILER}
    ${FMT_CROSSCOMPILING_ARGS}
    ${CMAKE_CURRENT_SOURCE_DIR}/project
  )
  add_test(NAME fmt_formatter_build
    COMMAND ${CMAKE_COMMAND} --build .
  )
  set_tests_properties(fmt_formatter_configure PROPERTIES
    FIXTURES_SETUP fmt_formatter
    LABELS "git_required;not_reproducible"
  )
  set_tests_properties(fmt_formatter_build PROPERTIES
    FIXTURES_REQUIRED fmt_formatter
    LABELS "git_required;not_reproducible"
  )
endif()
