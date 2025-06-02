cmake_minimum_required(VERSION 3.28)

project(json_test CXX)

set(NLOHMANN_JSON_BUILD_MODULES ON CACHE BOOL "Enable nlohmann.json module support")

add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/../.. ${CMAKE_CURRENT_BINARY_DIR}/tests)

add_executable(json_test main.cpp)
target_link_libraries(json_test 
    PRIVATE 
        nlohmann_json_modules
)

target_compile_definitions(json_test 
    PRIVATE NLOHMANN_JSON_BUILD_MODULES
)

target_compile_features(json_test PUBLIC cxx_std_20)
