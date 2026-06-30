cmake_minimum_required(VERSION 3.30)

# `import std;` (used by main.cpp) needs CMake's experimental C++ import-std
# support. The accepted token is CMake-version-specific; this value matches the
# CMake version pinned in the ci_module_cpp20 CI jobs (4.3.x). If that pin is
# bumped, this token must be updated to match (configuration fails loudly
# otherwise).
set(CMAKE_EXPERIMENTAL_CXX_IMPORT_STD "451f2fe2-a8a2-47c3-bc32-94786d8fc91b")

project(json_test CXX)

# import std; requires C++23 and the std library module
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_CXX_MODULE_STD ON)

set(NLOHMANN_JSON_BUILD_MODULES ON CACHE BOOL "Enable nlohmann.json module support")

add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/../.. ${CMAKE_CURRENT_BINARY_DIR}/tests)

add_executable(json_test main.cpp)
target_link_libraries(json_test
    PRIVATE
        nlohmann_json_modules
)

target_compile_features(json_test PRIVATE cxx_std_23)
