cmake_minimum_required(VERSION 3.0)
project(JSON_Benchmarks LANGUAGES CXX)

# set compiler flags
if((CMAKE_CXX_COMPILER_ID MATCHES GNU) OR (CMAKE_CXX_COMPILER_ID MATCHES Clang))
   set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -flto -DNDEBUG -O3")
endif()

# configure Google Benchmarks
set(BENCHMARK_ENABLE_TESTING OFF CACHE INTERNAL "" FORCE)
add_subdirectory(thirdparty/benchmark)

# header directories
include_directories(thirdparty)
include_directories(${CMAKE_SOURCE_DIR}/../single_include)

# copy test files to build folder
file(COPY ${CMAKE_SOURCE_DIR}/data DESTINATION .)
file(COPY ${CMAKE_SOURCE_DIR}/../test/data/regression/floats.json
          ${CMAKE_SOURCE_DIR}/../test/data/regression/unsigned_ints.json
          ${CMAKE_SOURCE_DIR}/../test/data/regression/signed_ints.json
    DESTINATION data/numbers)

# benchmark binary
add_executable(json_benchmarks src/benchmarks.cpp)
target_link_libraries(json_benchmarks benchmark ${CMAKE_THREAD_LIBS_INIT})
