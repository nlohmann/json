set(JSON_TEST_DATA_URL     https://github.com/nlohmann/json_test_data)
set(JSON_TEST_DATA_VERSION 3.0.0)

# if variable is set, use test data from given directory rather than downloading them
if(JSON_TestDataDirectory)
    message(STATUS "Using test data in ${JSON_TestDataDirectory}.")
    add_custom_target(download_test_data)
    file(WRITE ${CMAKE_BINARY_DIR}/include/test_data.hpp "#define TEST_DATA_DIRECTORY \"${JSON_TestDataDirectory}\"\n")
else()
    find_package(Git)
    # target to download test data
    add_custom_target(download_test_data
        COMMAND test -d json_test_data || ${GIT_EXECUTABLE} clone -c advice.detachedHead=false --branch v${JSON_TEST_DATA_VERSION} ${JSON_TEST_DATA_URL}.git --quiet --depth 1
        COMMENT "Downloading test data from ${JSON_TEST_DATA_URL} (v${JSON_TEST_DATA_VERSION})"
        WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
    )
    # create a header with the path to the downloaded test data
    file(WRITE ${CMAKE_BINARY_DIR}/include/test_data.hpp "#define TEST_DATA_DIRECTORY \"${CMAKE_BINARY_DIR}/json_test_data\"\n")
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
