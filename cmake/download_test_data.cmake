find_package(Git)

set(JSON_TEST_DATA_URL     https://github.com/nlohmann/json_test_data)
set(JSON_TEST_DATA_VERSION 1.0.0)

# target to download test data
add_custom_target(download_test_data
    COMMAND test -d json_test_data || ${GIT_EXECUTABLE} clone -c advice.detachedHead=false --branch v${JSON_TEST_DATA_VERSION} ${JSON_TEST_DATA_URL}.git --quiet --depth 1
    COMMENT "Downloading test data from ${JSON_TEST_DATA_URL} (v${JSON_TEST_DATA_VERSION})"
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
)

# create a header with the path to the downloaded test data
file(WRITE ${CMAKE_BINARY_DIR}/include/test_data.hpp "#define TEST_DATA_DIRECTORY \"${CMAKE_BINARY_DIR}/json_test_data\"\n")

# determine the operating system (for debug and support purposes)
find_program(UNAME_COMMAND uname)
find_program(VER_COMMAND ver)
if (UNAME_COMMAND)
    execute_process(COMMAND ${UNAME_COMMAND} -a OUTPUT_VARIABLE UNAME_COMMAND_RESULT OUTPUT_STRIP_TRAILING_WHITESPACE)
endif()
if (VER_COMMAND)
    execute_process(COMMAND ${VER_COMMAND} OUTPUT_VARIABLE VER_COMMAND_RESULT OUTPUT_STRIP_TRAILING_WHITESPACE)
endif()

message(STATUS "Operating system: ${UNAME_COMMAND_RESULT} ${VER_COMMAND_RESULT} ${CMAKE_SYSTEM}")
