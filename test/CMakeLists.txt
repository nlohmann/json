option(JSON_Sanitizer "Build test suite with Clang sanitizer" OFF)
option(JSON_Valgrind "Execute test suite with Valgrind" OFF)
option(JSON_NoExceptions "Build test suite without exceptions" OFF)
option(JSON_Coverage "Build test suite with coverage information" OFF)

# download test data
include(${CMAKE_CURRENT_SOURCE_DIR}/../cmake/download_test_data.cmake)

# test fixture to download test data
add_test(NAME "download_test_data" COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR} --target download_test_data)
set_tests_properties(download_test_data PROPERTIES FIXTURES_SETUP TEST_DATA)

if(JSON_Sanitizer)
    message(STATUS "Building test suite with Clang sanitizer")
    if(NOT MSVC)
        set(CMAKE_CXX_FLAGS "-g -O0 -fsanitize=address -fsanitize=undefined -fsanitize=integer -fsanitize=nullability -fno-omit-frame-pointer -fno-sanitize-recover=all -fsanitize-recover=unsigned-integer-overflow")
    endif()
endif()

if(JSON_Valgrind)
    find_program(CMAKE_MEMORYCHECK_COMMAND valgrind)
    message(STATUS "Executing test suite with Valgrind (${CMAKE_MEMORYCHECK_COMMAND})")
    set(memcheck_command "${CMAKE_MEMORYCHECK_COMMAND} ${CMAKE_MEMORYCHECK_COMMAND_OPTIONS} --error-exitcode=1 --leak-check=full")
    separate_arguments(memcheck_command)
endif()

if(JSON_NoExceptions)
    message(STATUS "Building test suite without exceptions")
    if(NOT MSVC)
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DJSON_NOEXCEPTION")
    endif()
    set(DOCTEST_TEST_FILTER --no-throw)
endif()

if(JSON_Coverage)
    message(STATUS "Building test suite with coverage information")

    # from https://github.com/RWTH-HPC/CMake-codecov/blob/master/cmake/FindGcov.cmake
    get_filename_component(COMPILER_PATH "${CMAKE_CXX_COMPILER}" PATH)
    string(REGEX MATCH "^[0-9]+" GCC_VERSION "${CMAKE_CXX_COMPILER_VERSION}")
    find_program(GCOV_BIN NAMES gcov-${GCC_VERSION} gcov HINTS ${COMPILER_PATH})

    # collect all source files from the chosen include dir
    file(GLOB_RECURSE SOURCE_FILES ${NLOHMANN_JSON_INCLUDE_BUILD_DIR}*.hpp)

    # add target to collect coverage information and generate HTML file
    # (filter script from https://stackoverflow.com/a/43726240/266378)
    add_custom_target(lcov_html
        COMMAND lcov --directory . --capture --output-file json.info --rc lcov_branch_coverage=1
        COMMAND lcov -e json.info ${SOURCE_FILES} --output-file json.info.filtered --gcov-tool ${GCOV_BIN} --rc lcov_branch_coverage=1
        COMMAND ${CMAKE_SOURCE_DIR}/test/thirdparty/imapdl/filterbr.py json.info.filtered > json.info.filtered.noexcept
        COMMAND genhtml --title "JSON for Modern C++" --legend --demangle-cpp --output-directory html --show-details --branch-coverage json.info.filtered.noexcept
        COMMENT "Generating HTML report test/html/index.html"
    )
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

set(files
    src/unit-algorithms.cpp
    src/unit-allocator.cpp
    src/unit-alt-string.cpp
    src/unit-assert_macro.cpp
    src/unit-bson.cpp
    src/unit-capacity.cpp
    src/unit-cbor.cpp
    src/unit-class_const_iterator.cpp
    src/unit-class_iterator.cpp
    src/unit-class_lexer.cpp
    src/unit-class_parser.cpp
    src/unit-comparison.cpp
    src/unit-concepts.cpp
    src/unit-constructor1.cpp
    src/unit-constructor2.cpp
    src/unit-convenience.cpp
    src/unit-conversions.cpp
    src/unit-deserialization.cpp
    src/unit-element_access1.cpp
    src/unit-element_access2.cpp
    src/unit-hash.cpp
    src/unit-inspection.cpp
    src/unit-items.cpp
    src/unit-iterators1.cpp
    src/unit-iterators2.cpp
    src/unit-json_patch.cpp
    src/unit-json_pointer.cpp
    src/unit-large_json.cpp
    src/unit-merge_patch.cpp
    src/unit-meta.cpp
    src/unit-modifiers.cpp
    src/unit-msgpack.cpp
    src/unit-noexcept.cpp
    src/unit-ordered_json.cpp
    src/unit-ordered_map.cpp
    src/unit-pointer_access.cpp
    src/unit-readme.cpp
    src/unit-reference_access.cpp
    src/unit-regression1.cpp
    src/unit-regression2.cpp
    src/unit-serialization.cpp
    src/unit-testsuites.cpp
    src/unit-to_chars.cpp
    src/unit-ubjson.cpp
    src/unit-udt.cpp
    src/unit-udt_macro.cpp
    src/unit-unicode.cpp
    src/unit-user_defined_input.cpp
    src/unit-wstring.cpp)

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

    if (JSON_Coverage)
        target_compile_options(${testcase} PRIVATE --coverage)
        target_link_libraries(${testcase} PRIVATE --coverage)
    endif()

    add_test(NAME "${testcase}"
        COMMAND ${testcase} ${DOCTEST_TEST_FILTER} --no-skip
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    )
    set_tests_properties("${testcase}" PROPERTIES LABELS "all" FIXTURES_REQUIRED TEST_DATA)

    if(JSON_Valgrind)
        add_test(NAME "${testcase}_valgrind"
            COMMAND ${memcheck_command} ${CMAKE_CURRENT_BINARY_DIR}/${testcase} ${DOCTEST_TEST_FILTER}
            WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
        )
        set_tests_properties("${testcase}_valgrind" PROPERTIES LABELS "valgrind")
    endif()
endforeach()

add_executable(json_unit EXCLUDE_FROM_ALL $<TARGET_OBJECTS:doctest_main> ${files})
target_compile_definitions(json_unit PRIVATE DOCTEST_CONFIG_SUPER_FAST_ASSERTS)
target_compile_options(json_unit PRIVATE
    $<$<CXX_COMPILER_ID:MSVC>:/EHsc;$<$<CONFIG:Release>:/Od>>
    $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wno-deprecated;-Wno-float-equal>
    $<$<CXX_COMPILER_ID:GNU>:-Wno-deprecated-declarations>
)
target_include_directories(json_unit PRIVATE ${CMAKE_BINARY_DIR}/include thirdparty/doctest thirdparty/fifo_map)
target_link_libraries(json_unit ${NLOHMANN_JSON_TARGET_NAME})
add_dependencies(json_unit download_test_data)

#############################################################################
# Test the generated build configs
#############################################################################

add_subdirectory(cmake_import)
add_subdirectory(cmake_import_minver)
add_subdirectory(cmake_add_subdirectory)
add_subdirectory(cmake_fetch_content)
add_subdirectory(cmake_target_include_directories)
