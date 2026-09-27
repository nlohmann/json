cmake_minimum_required(VERSION 3.14)
project(JSON_Benchmarks LANGUAGES CXX)

# set compiler flags
if((CMAKE_CXX_COMPILER_ID MATCHES GNU) OR (CMAKE_CXX_COMPILER_ID MATCHES Clang))
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -flto -DNDEBUG -O3")
endif()

# configure Google Benchmark; a fixed release, so that results stay comparable
set(JSON_GOOGLE_BENCHMARK_VERSION 1.9.5)
include(FetchContent)

# only the library is needed; -Werror would break the pinned release as soon as
# a newer compiler adds a warning
set(BENCHMARK_ENABLE_TESTING OFF CACHE BOOL "" FORCE)
set(BENCHMARK_ENABLE_INSTALL OFF CACHE BOOL "" FORCE)
set(BENCHMARK_ENABLE_WERROR OFF CACHE BOOL "" FORCE)

FetchContent_Declare(benchmark
    URL https://github.com/google/benchmark/archive/refs/tags/v${JSON_GOOGLE_BENCHMARK_VERSION}.tar.gz
    URL_HASH SHA256=9631341c82bac4a288bef951f8b26b41f69021794184ece969f8473977eaa340
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE
)
FetchContent_MakeAvailable(benchmark)

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
