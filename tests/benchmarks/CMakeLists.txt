cmake_minimum_required(VERSION 3.11...3.14)
project(JSON_Benchmarks LANGUAGES CXX)

# set compiler flags
if((CMAKE_CXX_COMPILER_ID MATCHES GNU) OR (CMAKE_CXX_COMPILER_ID MATCHES Clang))
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -flto -DNDEBUG -O3")
endif()

# configure Google Benchmarks
include(FetchContent)
FetchContent_Declare(
    benchmark
    GIT_REPOSITORY https://github.com/google/benchmark.git
    GIT_TAG origin/main
    GIT_SHALLOW TRUE
)

FetchContent_GetProperties(benchmark)
if(NOT benchmark_POPULATED)
    FetchContent_Populate(benchmark)
    set(BENCHMARK_ENABLE_TESTING OFF CACHE INTERNAL "" FORCE)
    add_subdirectory(${benchmark_SOURCE_DIR} ${benchmark_BINARY_DIR})
endif()

# download test data
set(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/../../cmake ${CMAKE_MODULE_PATH})
include(download_test_data)

# the header to benchmark; point this at a directory holding another version's
# nlohmann/json.hpp to compare versions (see README.md)
set(JSON_BENCHMARK_INCLUDE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../single_include" CACHE PATH
    "directory containing the nlohmann/json.hpp to benchmark")

# benchmark binary
add_executable(json_benchmarks src/benchmarks.cpp)
target_compile_features(json_benchmarks PRIVATE cxx_std_11)
target_link_libraries(json_benchmarks benchmark ${CMAKE_THREAD_LIBS_INIT})
add_dependencies(json_benchmarks download_test_data)
target_include_directories(json_benchmarks PRIVATE ${JSON_BENCHMARK_INCLUDE_DIR} ${CMAKE_BINARY_DIR}/include)
