if (${CMAKE_VERSION} VERSION_GREATER "3.11.0")
  add_test(NAME cmake_fetch_content_configure
    COMMAND ${CMAKE_COMMAND}
    -G "${CMAKE_GENERATOR}"
    -DCMAKE_CXX_COMPILER=${CMAKE_CXX_COMPILER}
    -DCMAKE_CXX_FLAGS=${CMAKE_CXX_FLAGS}
    -Dnlohmann_json_source=${PROJECT_SOURCE_DIR}
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
endif()
