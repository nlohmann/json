find_package(Git)

# target to download test data
add_custom_target(download_test_data
    COMMAND test -d json_test_data || ${GIT_EXECUTABLE} clone https://github.com/nlohmann/json_test_data.git --quiet --depth 1
    COMMENT "Downloading test data from https://github.com/nlohmann/json_test_data"
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
)

# create a header with the path to the downloaded test data
file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/include/test_data.hpp "#define TEST_DATA_DIRECTORY \"${CMAKE_BINARY_DIR}/json_test_data\"")
