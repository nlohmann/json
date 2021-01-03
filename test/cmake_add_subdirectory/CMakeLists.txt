add_test(NAME cmake_add_subdirectory_configure
  COMMAND ${CMAKE_COMMAND}
    -G "${CMAKE_GENERATOR}"
    -DCMAKE_CXX_COMPILER=${CMAKE_CXX_COMPILER}
    -Dnlohmann_json_source=${PROJECT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/project
)
add_test(NAME cmake_add_subdirectory_build
  COMMAND ${CMAKE_COMMAND} --build .
)
set_tests_properties(cmake_add_subdirectory_configure PROPERTIES
  FIXTURES_SETUP cmake_add_subdirectory
  LABELS not_reproducible
)
set_tests_properties(cmake_add_subdirectory_build PROPERTIES
  FIXTURES_REQUIRED cmake_add_subdirectory
  LABELS not_reproducible
)
