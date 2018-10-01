add_test(NAME cmake_import_minver_configure
  COMMAND ${CMAKE_COMMAND}
    -G "${CMAKE_GENERATOR}"
    -Dnlohmann_json_DIR=${PROJECT_BINARY_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/project
)
add_test(NAME cmake_import_minver_build
  COMMAND ${CMAKE_COMMAND} --build .
)
set_tests_properties(cmake_import_minver_configure PROPERTIES
  FIXTURES_SETUP cmake_import_minver
)
set_tests_properties(cmake_import_minver_build PROPERTIES
  FIXTURES_REQUIRED cmake_import_minver
)
