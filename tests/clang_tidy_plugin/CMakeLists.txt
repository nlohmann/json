include(CTest)

if(NOT LLVM_TOOLS_BINARY_DIR)
    message(FATAL_ERROR "Could not determine LLVM binary directory")
endif()

add_test(NAME modernize-nlohmann-json-explicit-conversions-check COMMAND ${CMAKE_COMMAND} -E env PATH=${LLVM_TOOLS_BINARY_DIR}:$ENV{PATH}
  ${CMAKE_CURRENT_LIST_DIR}/check_clang_tidy.py -std=c++17
  -plugin=$<TARGET_FILE:NlohmannJsonClangTidyPlugin>
  ${CMAKE_CURRENT_LIST_DIR}/modernize-nlohmann-json-explicit-conversions.cpp modernize-nlohmann-json-explicit-conversions temp)
