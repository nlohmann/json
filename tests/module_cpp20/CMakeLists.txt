# `import std;` (used by main.cpp) is supported without experimental opt-in
# since CMake 4.5: it is available to every target that scans for C++ modules.
cmake_minimum_required(VERSION 4.5)

project(json_test CXX)

# import std; requires C++23 and the std library module
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(NLOHMANN_JSON_BUILD_MODULES ON CACHE BOOL "Enable nlohmann.json module support")

add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/../.. ${CMAKE_CURRENT_BINARY_DIR}/tests)

add_executable(json_test main.cpp)
target_link_libraries(json_test
    PRIVATE
        nlohmann_json_modules
)

target_compile_features(json_test PRIVATE cxx_std_23)
