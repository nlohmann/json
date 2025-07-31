set(JSON_TEST_DATA_URL     https://github.com/nlohmann/json_test_data)
set(JSON_TEST_DATA_VERSION 3.1.0)

include(ExternalProject)

# if variable is set, use test data from given directory rather than downloading them
if(JSON_TestDataDirectory)
    message(STATUS "Using test data in ${JSON_TestDataDirectory}.")
    add_custom_target(download_test_data)
    file(WRITE ${CMAKE_BINARY_DIR}/include/test_data.hpp "#define TEST_DATA_DIRECTORY \"${JSON_TestDataDirectory}\"\n")
else()
    # create a header with the path to the downloaded test data
    file(WRITE ${CMAKE_BINARY_DIR}/include/test_data.hpp "#define TEST_DATA_DIRECTORY \"${CMAKE_BINARY_DIR}/test_files\"\n")

    # download test data from GitHub release
    ExternalProject_Add(download_test_data_project
        URL "${JSON_TEST_DATA_URL}/archive/refs/tags/v${JSON_TEST_DATA_VERSION}.zip"
        SOURCE_DIR "${CMAKE_BINARY_DIR}/test_files"
        CONFIGURE_COMMAND ""
        BUILD_COMMAND ""
        INSTALL_COMMAND ""
        LOG_DOWNLOAD TRUE
        DOWNLOAD_EXTRACT_TIMESTAMP TRUE
        EXCLUDE_FROM_ALL TRUE
    )

    # target to download test data
    add_custom_target(download_test_data
        DEPENDS download_test_data_project
    )
endif()

# determine the operating system (for debug and support purposes)
find_program(UNAME_COMMAND uname)
find_program(VER_COMMAND ver)
find_program(LSB_RELEASE_COMMAND lsb_release)
find_program(SW_VERS_COMMAND sw_vers)
set(OS_VERSION_STRINGS "${CMAKE_SYSTEM}")
if (VER_COMMAND)
    execute_process(COMMAND ${VER_COMMAND} OUTPUT_VARIABLE VER_COMMAND_RESULT OUTPUT_STRIP_TRAILING_WHITESPACE)
    set(OS_VERSION_STRINGS "${OS_VERSION_STRINGS}; ${VER_COMMAND_RESULT}")
endif()
if (SW_VERS_COMMAND)
    execute_process(COMMAND ${SW_VERS_COMMAND} OUTPUT_VARIABLE SW_VERS_COMMAND_RESULT OUTPUT_STRIP_TRAILING_WHITESPACE ERROR_QUIET)
    string(REGEX REPLACE "[ ]*\n" "; " SW_VERS_COMMAND_RESULT "${SW_VERS_COMMAND_RESULT}")
    set(OS_VERSION_STRINGS "${OS_VERSION_STRINGS}; ${SW_VERS_COMMAND_RESULT}")
endif()
if (LSB_RELEASE_COMMAND)
    execute_process(COMMAND ${LSB_RELEASE_COMMAND} -a OUTPUT_VARIABLE LSB_RELEASE_COMMAND_RESULT OUTPUT_STRIP_TRAILING_WHITESPACE ERROR_QUIET)
    string(REGEX REPLACE "[ ]*\n" "; " LSB_RELEASE_COMMAND_RESULT "${LSB_RELEASE_COMMAND_RESULT}")
    set(OS_VERSION_STRINGS "${OS_VERSION_STRINGS}; ${LSB_RELEASE_COMMAND_RESULT}")
endif()
if (UNAME_COMMAND)
    execute_process(COMMAND ${UNAME_COMMAND} -a OUTPUT_VARIABLE UNAME_COMMAND_RESULT OUTPUT_STRIP_TRAILING_WHITESPACE ERROR_QUIET)
    set(OS_VERSION_STRINGS "${OS_VERSION_STRINGS}; ${UNAME_COMMAND_RESULT}")
endif()

message(STATUS "Operating system: ${OS_VERSION_STRINGS}")

# determine the compiler (for debug and support purposes)
if (MSVC)
    execute_process(COMMAND ${CMAKE_CXX_COMPILER} OUTPUT_VARIABLE CXX_VERSION_RESULT OUTPUT_STRIP_TRAILING_WHITESPACE ERROR_VARIABLE CXX_VERSION_RESULT ERROR_STRIP_TRAILING_WHITESPACE)
    set(CXX_VERSION_RESULT "${CXX_VERSION_RESULT}; MSVC_VERSION=${MSVC_VERSION}; MSVC_TOOLSET_VERSION=${MSVC_TOOLSET_VERSION}")
else()
    execute_process(COMMAND ${CMAKE_CXX_COMPILER} --version OUTPUT_VARIABLE CXX_VERSION_RESULT OUTPUT_STRIP_TRAILING_WHITESPACE)
endif()
string(REGEX REPLACE "[ ]*\n" "; " CXX_VERSION_RESULT "${CXX_VERSION_RESULT}")
message(STATUS "Compiler: ${CXX_VERSION_RESULT}")

# determine used C++ standard library (for debug and support purposes)
if(CMAKE_CROSSCOMPILING)
    set(LIBCPP_VERSION_OUTPUT_CACHED "could not be detected due to cross-compiling" CACHE STRING "Detected C++ standard library version")
endif()
if(NOT DEFINED LIBCPP_VERSION_OUTPUT_CACHED)
    try_run(RUN_RESULT_VAR COMPILE_RESULT_VAR
        "${CMAKE_BINARY_DIR}" SOURCES "${CMAKE_SOURCE_DIR}/cmake/detect_libcpp_version.cpp"
        RUN_OUTPUT_VARIABLE LIBCPP_VERSION_OUTPUT
        COMPILE_OUTPUT_VARIABLE LIBCPP_VERSION_COMPILE_OUTPUT
    )
    if(NOT LIBCPP_VERSION_OUTPUT)
        set(LIBCPP_VERSION_OUTPUT "Unknown")
        message(AUTHOR_WARNING "Failed to compile cmake/detect_libcpp_version to detect the used C++ standard library. This does not affect the library or the test cases. Please still create an issue at https://github.com/nlohmann/json to investigate this.\n${LIBCPP_VERSION_COMPILE_OUTPUT}")
    endif()
    set(LIBCPP_VERSION_OUTPUT_CACHED "${LIBCPP_VERSION_OUTPUT}" CACHE STRING "Detected C++ standard library version")
endif()

message(STATUS "C++ standard library: ${LIBCPP_VERSION_OUTPUT_CACHED}")
