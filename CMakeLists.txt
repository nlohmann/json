cmake_minimum_required(VERSION 2.8)

project(json CXX)

add_library(${PROJECT_NAME} INTERFACE IMPORTED GLOBAL)
set_target_properties(${PROJECT_NAME} PROPERTIES
    INTERFACE_INCLUDE_DIRECTORIES "${CMAKE_CURRENT_SOURCE_DIR}/src")

set(UNIT_TEST_NAME "json_unit")
add_executable(${UNIT_TEST_NAME}
    "test/catch.hpp" "test/unit.cpp")
set_target_properties(${UNIT_TEST_NAME} PROPERTIES
    CXX_STANDARD 11
    CXX_STANDARD_REQUIRED ON
    COMPILE_DEFINITIONS "$<$<CXX_COMPILER_ID:MSVC>:_SCL_SECURE_NO_WARNINGS>"
    COMPILE_OPTIONS "$<$<CXX_COMPILER_ID:MSVC>:/EHsc;$<$<CONFIG:Release>:/Od>>")
target_include_directories(${UNIT_TEST_NAME} PRIVATE "test")
target_link_libraries(${UNIT_TEST_NAME} ${PROJECT_NAME})
