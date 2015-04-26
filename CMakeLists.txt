cmake_minimum_required(VERSION 3.1.2)

project(json CXX)

add_executable(json_unit
    src/json.hpp test/catch.hpp test/unit.cpp
)

set(CMAKE_CXX_FLAGS
    "-std=c++11 -stdlib=libc++"
)

include_directories(
    src test
)
