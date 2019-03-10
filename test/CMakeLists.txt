option(JSON_Sanitizer "Build test suite with Clang sanitizer" OFF)
option(JSON_Valgrind "Execute test suite with Valgrind" OFF)
option(JSON_NoExceptions "Build test suite without exceptions" OFF)
option(JSON_Coverage "Build test suite with coverage information" OFF)

if(JSON_Sanitizer)
    message(STATUS "Building test suite with Clang sanitizer")
    if(NOT MSVC)
        set(CMAKE_CXX_FLAGS "-g -O2 -fsanitize=address -fsanitize=undefined -fno-omit-frame-pointer")
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
    set(CATCH_TEST_FILTER -e)
endif()

if(JSON_Coverage)
    message(STATUS "Building test suite with coverage information")
    if(NOT "${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
        message(FATAL_ERROR "JSON_Coverage requires GCC.")
    endif()

    # enable profiling
    set(CMAKE_CXX_FLAGS "--coverage -g -O0 -fprofile-arcs -ftest-coverage")

    # from https://github.com/RWTH-HPC/CMake-codecov/blob/master/cmake/FindGcov.cmake
    get_filename_component(COMPILER_PATH "${CMAKE_CXX_COMPILER}" PATH)
    string(REGEX MATCH "^[0-9]+" GCC_VERSION "${CMAKE_CXX_COMPILER_VERSION}")
    find_program(GCOV_BIN NAMES gcov-${GCC_VERSION} gcov HINTS ${COMPILER_PATH})

    # collect all source files from the chosen include dir
    file(GLOB_RECURSE SOURCE_FILES ${NLOHMANN_JSON_INCLUDE_BUILD_DIR}*.hpp)

    # add target to collect coverage information and generate HTML file
    # (filter script from https://stackoverflow.com/a/43726240/266378)
    add_custom_target(lcov_html
        COMMAND lcov --directory . --capture --output-file json.info --gcov-tool ${GCOV_BIN} --rc lcov_branch_coverage=1
        COMMAND lcov -e json.info ${SOURCE_FILES} --output-file json.info.filtered --rc lcov_branch_coverage=1
        COMMAND ${CMAKE_SOURCE_DIR}/test/thirdparty/imapdl/filterbr.py json.info.filtered > json.info.filtered.noexcept
        COMMAND genhtml --title "JSON for Modern C++" --legend --demangle-cpp --output-directory html --show-details --branch-coverage json.info.filtered.noexcept
        COMMENT "Generating HTML report test/html/index.html"
    )
endif()

#############################################################################
# Catch library with the main function to speed up build
#############################################################################

add_library(catch_main OBJECT
    "src/unit.cpp"
)
set_target_properties(catch_main PROPERTIES
    COMPILE_DEFINITIONS "$<$<CXX_COMPILER_ID:MSVC>:_SCL_SECURE_NO_WARNINGS>"
    COMPILE_OPTIONS "$<$<CXX_COMPILER_ID:MSVC>:/EHsc;$<$<CONFIG:Release>:/Od>>"
)
if (${CMAKE_VERSION} VERSION_LESS "3.8.0") 
    target_compile_features(catch_main PUBLIC cxx_range_for)
else()
    target_compile_features(catch_main PUBLIC cxx_std_11)
endif()
target_include_directories(catch_main PRIVATE "thirdparty/catch")

# https://stackoverflow.com/questions/2368811/how-to-set-warning-level-in-cmake
if(MSVC)
    # Force to always compile with W4
    if(CMAKE_CXX_FLAGS MATCHES "/W[0-4]")
        string(REGEX REPLACE "/W[0-4]" "/W4" CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}")
    else()
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /W4")
    endif()

    # Disable warning C4389: '==': signed/unsigned mismatch
	# Disable warning C4309: 'static_cast': truncation of constant value
	# Disable warning C4566: character represented by universal-character-name '\uFF01' cannot be represented in the current code page (1252)
	# Disable warning C4996: 'nlohmann::basic_json<std::map,std::vector,std::string,bool,int64_t,uint64_t,double,std::allocator,nlohmann::adl_serializer>::operator <<': was declared deprecated
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /wd4389 /wd4309 /wd4566 /wd4996")
	
	# https://github.com/nlohmann/json/issues/1114
	set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} /bigobj")
endif()

#############################################################################
# one executable for each unit test file
#############################################################################

file(GLOB files "src/unit-*.cpp")
foreach(file ${files})
    get_filename_component(file_basename ${file} NAME_WE)
    string(REGEX REPLACE "unit-([^$]+)" "test-\\1" testcase ${file_basename})

    add_executable(${testcase} $<TARGET_OBJECTS:catch_main> ${file})
    target_compile_definitions(${testcase} PRIVATE
      CATCH_CONFIG_FAST_COMPILE
      $<$<CXX_COMPILER_ID:MSVC>:_SCL_SECURE_NO_WARNINGS>
    )
    target_compile_options(${testcase} PRIVATE
        $<$<CXX_COMPILER_ID:MSVC>:/EHsc;$<$<CONFIG:Release>:/Od>>
        $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wno-deprecated;-Wno-float-equal>
        $<$<CXX_COMPILER_ID:GNU>:-Wno-deprecated-declarations>
    )
    target_include_directories(${testcase} PRIVATE
        thirdparty/catch
        thirdparty/fifo_map
    )
    target_link_libraries(${testcase} ${NLOHMANN_JSON_TARGET_NAME})

    add_test(NAME "${testcase}_default"
      COMMAND ${testcase} ${CATCH_TEST_FILTER}
      WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    )
    set_tests_properties("${testcase}_default" PROPERTIES LABELS "default")

    add_test(NAME "${testcase}_all"
      COMMAND ${testcase} ${CATCH_TEST_FILTER} "*"
      WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    )
    set_tests_properties("${testcase}_all" PROPERTIES LABELS "all")

    if(JSON_Valgrind)
        add_test(NAME "${testcase}_valgrind"
          COMMAND ${memcheck_command} ${CMAKE_CURRENT_BINARY_DIR}/${testcase} ${CATCH_TEST_FILTER}
          WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
        )
        set_tests_properties("${testcase}_valgrind" PROPERTIES LABELS "valgrind")
    endif()
endforeach()

#############################################################################
# Test the generated build configs
#############################################################################
add_subdirectory(cmake_import)
add_subdirectory(cmake_import_minver)
add_subdirectory(cmake_add_subdirectory)
