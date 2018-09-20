cmake_minimum_required(VERSION 3.8)
project(JSON_Benchmarks LANGUAGES CXX)

# set compiler flags
if((CMAKE_CXX_COMPILER_ID MATCHES GNU) OR (CMAKE_CXX_COMPILER_ID MATCHES Clang))
   set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -flto -DNDEBUG -O3")
endif()

# configure Google Benchmarks
set(BENCHMARK_ENABLE_TESTING OFF CACHE INTERNAL "" FORCE)
add_subdirectory(thirdparty/benchmark)

# header directories
include_directories(thirdparty)
include_directories(${CMAKE_SOURCE_DIR}/../single_include)

include(ExternalData)

set(ExternalData_URL_TEMPLATES
  "https://github.com/theodelrieu/cmake_external_data/raw/master/json/%(algo)/regression/%(hash)"
  "https://github.com/theodelrieu/cmake_external_data/raw/master/json/%(algo)/nativejson-benchmark/%(hash)"
  "https://github.com/theodelrieu/cmake_external_data/raw/master/json/%(algo)/jeopardy/%(hash)"
)

ExternalData_Expand_Arguments(json_benchmark_data _ DATA{data/,RECURSE:,REGEX:.*})
ExternalData_Add_Target(json_benchmark_data)

# benchmark binary
add_executable(json_benchmarks src/benchmarks.cpp)
target_compile_features(json_benchmarks PRIVATE cxx_std_11)
target_link_libraries(json_benchmarks benchmark ${CMAKE_THREAD_LIBS_INIT})
add_dependencies(json_benchmarks json_benchmark_data)
