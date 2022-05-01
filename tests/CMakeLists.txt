cmake_minimum_required(VERSION 3.13)

option(JSON_Valgrind    "Execute test suite with Valgrind." OFF)
option(JSON_FastTests   "Skip expensive/slow tests." OFF)

set(JSON_TestStandards "" CACHE STRING "The list of standards to test explicitly.")

include(test)

#############################################################################
# override standard support
#############################################################################

# Clang only supports C++17 starting from Clang 5.0
if (CMAKE_CXX_COMPILER_ID STREQUAL "Clang" AND CMAKE_CXX_COMPILER_VERSION VERSION_LESS 5.0)
    unset(compiler_supports_cpp_17)
endif()
# MSVC 2015 (14.0) does not support C++17
if (CMAKE_CXX_COMPILER_ID STREQUAL "MSVC" AND CMAKE_CXX_COMPILER_VERSION VERSION_LESS 19.1)
    unset(compiler_supports_cpp_17)
endif()

# Clang C++20 support appears insufficient prior to Clang 9.0 (based on CI build failure)
if (CMAKE_CXX_COMPILER_ID STREQUAL "Clang" AND CMAKE_CXX_COMPILER_VERSION VERSION_LESS 9.0)
    unset(compiler_supports_cpp_20)
endif()
# GCC started supporting C++20 features in 8.0 but a test for #3070 segfaults prior to 9.0
if (CMAKE_CXX_COMPILER_ID STREQUAL "GNU" AND CMAKE_CXX_COMPILER_VERSION VERSION_LESS 9.0)
    unset(compiler_supports_cpp_20)
endif()

#############################################################################
# test_main library with shared code to speed up build and common settings
#############################################################################

add_library(test_main OBJECT src/unit.cpp)
target_compile_definitions(test_main PUBLIC
    DOCTEST_CONFIG_SUPER_FAST_ASSERTS
    JSON_TEST_KEEP_MACROS
)
target_compile_features(test_main PRIVATE cxx_std_11)
target_compile_options(test_main PUBLIC
    $<$<CXX_COMPILER_ID:MSVC>:/EHsc;$<$<CONFIG:Release>:/Od>>
    # MSVC: Force to always compile with W4
    #       Disable warning C4566: character represented by universal-character-name '\uFF01'
    #                              cannot be represented in the current code page (1252)
    #       Disable warning C4996: 'nlohmann::basic_json<...>::operator <<': was declared deprecated
    $<$<CXX_COMPILER_ID:MSVC>:/W4 /wd4566 /wd4996>
    # https://github.com/nlohmann/json/issues/1114
    $<$<CXX_COMPILER_ID:MSVC>:/bigobj> $<$<BOOL:${MINGW}>:-Wa,-mbig-obj>

    # https://github.com/nlohmann/json/pull/3229
    $<$<CXX_COMPILER_ID:Intel>:-diag-disable=2196>

    $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wno-deprecated;-Wno-float-equal>
    $<$<CXX_COMPILER_ID:GNU>:-Wno-deprecated-declarations>
    $<$<CXX_COMPILER_ID:Intel>:-diag-disable=1786>
)
target_include_directories(test_main PUBLIC
    thirdparty/doctest
    thirdparty/fifo_map
    ${PROJECT_BINARY_DIR}/include
)
target_link_libraries(test_main PUBLIC ${NLOHMANN_JSON_TARGET_NAME})

#############################################################################
# define test- and standard-specific build settings
#############################################################################

if (CMAKE_CXX_COMPILER_ID STREQUAL "GNU"
    AND CMAKE_CXX_COMPILER_VERSION VERSION_GREATER_EQUAL 8.0
    AND CMAKE_CXX_COMPILER_VERSION VERSION_LESS 9.0 AND NOT MINGW)
    # fix for https://gcc.gnu.org/bugzilla/show_bug.cgi?id=90050
    json_test_set_test_options(all CXX_STANDARDS 17 LINK_LIBRARIES stdc++fs)
endif()

if (CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
    # avoid stack overflow, see https://github.com/nlohmann/json/issues/2955
    json_test_set_test_options("test-cbor;test-msgpack;test-ubjson;test-bjdata" LINK_OPTIONS /STACK:4000000)
endif()

# disable exceptions for test-disabled_exceptions
json_test_set_test_options(test-disabled_exceptions COMPILE_DEFINITIONS JSON_NOEXCEPTION)
if (CMAKE_CXX_COMPILER_ID STREQUAL "Clang" OR CMAKE_CXX_COMPILER_ID STREQUAL "AppleClang" OR CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
json_test_set_test_options(test-disabled_exceptions COMPILE_OPTIONS -fno-exceptions)
elseif (CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
    # disabled due to https://github.com/nlohmann/json/discussions/2824
    #json_test_set_test_options(test-disabled_exceptions COMPILE_DEFINITIONS _HAS_EXCEPTIONS=0 COMPILE_OPTIONS /EH)
endif()

#############################################################################
# add unit tests
#############################################################################

if("${JSON_TestStandards}" STREQUAL "")
    set(test_cxx_standards 11 14 17 20 23)
    unset(test_force)
else()
    set(test_cxx_standards ${JSON_TestStandards})
    set(test_force FORCE)
endif()

# Print selected standards marking unavailable ones with brackets
set(msg_standards "")
foreach(cxx_standard ${test_cxx_standards})
    if(compiler_supports_cpp_${cxx_standard})
        list(APPEND msg_standards ${cxx_standard})
    else()
        list(APPEND msg_standards [${cxx_standard}])
    endif()
endforeach()
string(JOIN " " msg_standards ${msg_standards})
set(msg "Testing standards: ${msg_standards}")
if(test_force)
    string(APPEND msg " (forced)")
endif()
message(STATUS "${msg}")

# *DO* use json_test_set_test_options() above this line

file(GLOB files src/unit-*.cpp)
foreach(file ${files})
    json_test_add_test_for(${file} MAIN test_main CXX_STANDARDS ${test_cxx_standards} ${test_force})
endforeach()

# *DO NOT* use json_test_set_test_options() below this line

#############################################################################
# Test the generated build configs
#############################################################################

# these tests depend on the generated file nlohmann_jsonConfig.cmake
if (JSON_Install)
    add_subdirectory(cmake_import)
    add_subdirectory(cmake_import_minver)
endif()

add_subdirectory(cmake_add_subdirectory)
add_subdirectory(cmake_fetch_content)
add_subdirectory(cmake_fetch_content2)
add_subdirectory(cmake_target_include_directories)
