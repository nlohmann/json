cmake_minimum_required(VERSION 3.1.2)

project(json CXX)

add_executable(json_unit
    src/json.hpp test/catch.hpp test/unit.cpp
)

target_compile_features(json_unit
    PRIVATE cxx_range_for
)

include_directories(
    src test
)
