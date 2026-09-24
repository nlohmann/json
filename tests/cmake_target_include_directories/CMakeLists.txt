add_test(NAME cmake_target_include_directories_configure
  COMMAND ${CMAKE_COMMAND}
    -G "${CMAKE_GENERATOR}"
    -DCMAKE_CXX_COMPILER=${CMAKE_CXX_COMPILER}
    -DCMAKE_CXX_FLAGS=${CMAKE_CXX_FLAGS}
    -Dnlohmann_json_source=${PROJECT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/project
)
add_test(NAME cmake_target_include_directories_build
    COMMAND ${CMAKE_COMMAND} --build .
)
set_tests_properties(cmake_target_include_directories_configure PROPERTIES
    FIXTURES_SETUP cmake_target_include_directories
    LABELS not_reproducible
)
set_tests_properties(cmake_target_include_directories_build PROPERTIES
    FIXTURES_REQUIRED cmake_target_include_directories
    LABELS not_reproducible
)
