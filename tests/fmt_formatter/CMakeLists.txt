# fmt's CMakeLists.txt unconditionally sets the VERSION/SOVERSION/DEBUG_POSTFIX
# properties on its (always-configured) INTERFACE_LIBRARY "fmt-header-only" target;
# CMake rejected those properties on INTERFACE_LIBRARY targets before CMake 3.19
if (${CMAKE_VERSION} VERSION_GREATER_EQUAL "3.19.0")
  add_test(NAME fmt_formatter_configure
    COMMAND ${CMAKE_COMMAND}
    -G "${CMAKE_GENERATOR}"
    -DCMAKE_CXX_COMPILER=${CMAKE_CXX_COMPILER}
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
