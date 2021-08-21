option(JSON_Valgrind    "Execute test suite with Valgrind." OFF)
option(JSON_FastTests   "Skip expensive/slow tests." OFF)

# download test data
include(${CMAKE_CURRENT_SOURCE_DIR}/../cmake/download_test_data.cmake)

# test fixture to download test data
add_test(NAME "download_test_data" COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR} --target download_test_data)
set_tests_properties(download_test_data PROPERTIES FIXTURES_SETUP TEST_DATA)

if(JSON_Valgrind)
    find_program(CMAKE_MEMORYCHECK_COMMAND valgrind)
    message(STATUS "Executing test suite with Valgrind (${CMAKE_MEMORYCHECK_COMMAND})")
    set(memcheck_command "${CMAKE_MEMORYCHECK_COMMAND} ${CMAKE_MEMORYCHECK_COMMAND_OPTIONS} --error-exitcode=1 --leak-check=full")
    separate_arguments(memcheck_command)
endif()

#############################################################################
# doctest library with the main function to speed up build
#############################################################################

add_library(doctest_main OBJECT src/unit.cpp)
set_target_properties(doctest_main PROPERTIES
    COMPILE_DEFINITIONS "$<$<CXX_COMPILER_ID:MSVC>:_SCL_SECURE_NO_WARNINGS>"
    COMPILE_OPTIONS "$<$<CXX_COMPILER_ID:MSVC>:/EHsc;$<$<CONFIG:Release>:/Od>>"
)
if (${CMAKE_VERSION} VERSION_LESS "3.8.0")
    target_compile_features(doctest_main PUBLIC cxx_range_for)
else()
    target_compile_features(doctest_main PUBLIC cxx_std_11)
endif()
target_include_directories(doctest_main PRIVATE "thirdparty/doctest")

# https://stackoverflow.com/questions/2368811/how-to-set-warning-level-in-cmake
if(MSVC)
    # Force to always compile with W4
    if(CMAKE_CXX_FLAGS MATCHES "/W[0-4]")
        string(REGEX REPLACE "/W[0-4]" "/W4" CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}")
    else()
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /W4")
    endif()

	# Disable warning C4566: character represented by universal-character-name '\uFF01' cannot be represented in the current code page (1252)
	# Disable warning C4996: 'nlohmann::basic_json<std::map,std::vector,std::string,bool,int64_t,uint64_t,double,std::allocator,nlohmann::adl_serializer>::operator <<': was declared deprecated
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /wd4566 /wd4996")

	# https://github.com/nlohmann/json/issues/1114
	set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} /bigobj")
endif()

#############################################################################
# one executable for each unit test file
#############################################################################

file(GLOB files src/unit-*.cpp)

foreach(file ${files})
    get_filename_component(file_basename ${file} NAME_WE)
    string(REGEX REPLACE "unit-([^$]+)" "test-\\1" testcase ${file_basename})

    add_executable(${testcase} $<TARGET_OBJECTS:doctest_main> ${file})
    target_compile_definitions(${testcase} PRIVATE DOCTEST_CONFIG_SUPER_FAST_ASSERTS)
    target_compile_options(${testcase} PRIVATE
        $<$<CXX_COMPILER_ID:MSVC>:/EHsc;$<$<CONFIG:Release>:/Od>>
        $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wno-deprecated;-Wno-float-equal>
        $<$<CXX_COMPILER_ID:GNU>:-Wno-deprecated-declarations>
    )
    target_include_directories(${testcase} PRIVATE ${CMAKE_BINARY_DIR}/include thirdparty/doctest thirdparty/fifo_map)
    target_link_libraries(${testcase} PRIVATE ${NLOHMANN_JSON_TARGET_NAME})

    if (JSON_FastTests)
        add_test(NAME "${testcase}"
            COMMAND ${testcase} ${DOCTEST_TEST_FILTER}
            WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
        )
    else()
        add_test(NAME "${testcase}"
            COMMAND ${testcase} ${DOCTEST_TEST_FILTER} --no-skip
            WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
        )
    endif()
    set_tests_properties("${testcase}" PROPERTIES LABELS "all" FIXTURES_REQUIRED TEST_DATA)

    if(JSON_Valgrind)
        add_test(NAME "${testcase}_valgrind"
            COMMAND ${memcheck_command} ${CMAKE_CURRENT_BINARY_DIR}/${testcase} ${DOCTEST_TEST_FILTER}
            WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
        )
        set_tests_properties("${testcase}_valgrind" PROPERTIES LABELS "valgrind" FIXTURES_REQUIRED TEST_DATA)
    endif()
endforeach()

# disable exceptions for test-disabled_exceptions
target_compile_definitions(test-disabled_exceptions PUBLIC JSON_NOEXCEPTION)
if (CMAKE_CXX_COMPILER_ID STREQUAL "Clang" OR CMAKE_CXX_COMPILER_ID STREQUAL "AppleClang" OR CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    target_compile_options(test-disabled_exceptions PUBLIC -fno-exceptions)
elseif (CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
    # disabled due to https://github.com/nlohmann/json/discussions/2824
    #target_compile_options(test-disabled_exceptions PUBLIC /EH)
    #target_compile_definitions(test-disabled_exceptions PUBLIC _HAS_EXCEPTIONS=0)
endif()

# avoid stack overflow, see https://github.com/nlohmann/json/issues/2955
if (CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
    set_property(TARGET test-cbor APPEND_STRING PROPERTY LINK_FLAGS " /STACK:4000000")
    set_property(TARGET test-msgpack APPEND_STRING PROPERTY LINK_FLAGS " /STACK:4000000")
    set_property(TARGET test-ubjson APPEND_STRING PROPERTY LINK_FLAGS " /STACK:4000000")
endif()

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
add_subdirectory(cmake_target_include_directories)
