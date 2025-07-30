cmake_minimum_required(VERSION 3.11...4.0)

project(JSON_TESTS LANGUAGES NONE)

include(FetchContent)
FetchContent_Declare(
    json_test_data
    GIT_REPOSITORY ${JSON_TEST_DATA_URL}
    GIT_TAG v${JSON_TEST_DATA_VERSION}
    GIT_SHALLOW ON
    GIT_PROGRESS ON
)

message(STATUS "Downloading test data from ${JSON_TEST_DATA_URL} (v${JSON_TEST_DATA_VERSION})")
FetchContent_MakeAvailable(json_test_data)
