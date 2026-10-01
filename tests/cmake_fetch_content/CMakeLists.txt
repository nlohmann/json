add_test(NAME cmake_fetch_content_configure
  COMMAND ${CMAKE_COMMAND}
    -G "${CMAKE_GENERATOR}"
    -A "${CMAKE_GENERATOR_PLATFORM}"
    -T "${CMAKE_GENERATOR_TOOLSET}"
    -DCMAKE_CXX_COMPILER=${CMAKE_CXX_COMPILER}
    -DCMAKE_CXX_FLAGS=${CMAKE_CXX_FLAGS}
    ${CMAKE_CURRENT_SOURCE_DIR}/project
)
add_test(NAME cmake_fetch_content_build
  COMMAND ${CMAKE_COMMAND} --build .
)
set_tests_properties(cmake_fetch_content_configure PROPERTIES
  FIXTURES_SETUP cmake_fetch_content
  LABELS "git_required;not_reproducible"
)
set_tests_properties(cmake_fetch_content_build PROPERTIES
  FIXTURES_REQUIRED cmake_fetch_content
  LABELS "git_required;not_reproducible"
)
