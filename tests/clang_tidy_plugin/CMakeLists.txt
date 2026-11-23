include(CTest)

if(NOT LLVM_TOOLS_BINARY_DIR)
    message(FATAL_ERROR "Could not determine LLVM binary directory")
endif()

add_test(NAME modernize-nlohmann-json-explicit-conversions-output-check COMMAND ${CMAKE_COMMAND} -E env PATH=${LLVM_TOOLS_BINARY_DIR}:$ENV{PATH}
  ${CMAKE_CURRENT_LIST_DIR}/check_clang_tidy.py -std=c++17
  -plugin=$<TARGET_FILE:NlohmannJsonClangTidyPlugin>
  ${CMAKE_CURRENT_LIST_DIR}/modernize-nlohmann-json-explicit-conversions.cpp modernize-nlohmann-json-explicit-conversions temp)

file(MAKE_DIRECTORY "${CMAKE_BINARY_DIR}/test_artifacts")

# Define the test
add_test(
    NAME modernize-nlohmann-json-explicit-conversions-compile-check
    COMMAND ${CMAKE_COMMAND}
      "-DTEMPLATE_FILE=${CMAKE_CURRENT_LIST_DIR}/modernize-nlohmann-json-explicit-conversions.cpp"
      "-DTEST_WORK_DIR=${CMAKE_BINARY_DIR}/test_artifacts"
      "-DCLANG_TIDY_TOOL=${CLANG_TIDY_TOOL}"
      "-DCXX_COMPILER=${CMAKE_CXX_COMPILER}"
      "-DINCLUDE_PATH=${CMAKE_SOURCE_DIR}/single_include"
      "-DPLUGIN_PATH=$<TARGET_FILE:NlohmannJsonClangTidyPlugin>"
        -P "${CMAKE_CURRENT_LIST_DIR}/clang_tidy_compile_test.cmake"
)

# Set test working directory
set_tests_properties(modernize-nlohmann-json-explicit-conversions-compile-check PROPERTIES
    WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/test_artifacts"
)
