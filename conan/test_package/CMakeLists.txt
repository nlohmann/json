project(PackageTest CXX)
cmake_minimum_required(VERSION 3.0)
add_compile_options(-std=c++11)

include(${CMAKE_BINARY_DIR}/conanbuildinfo.cmake)
conan_basic_setup()

add_executable(example example.cpp)
target_link_libraries(example ${CONAN_LIBS})