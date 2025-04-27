cmake_minimum_required(VERSION 3.28)

project(json_test CXX)

add_executable(json_test)

target_sources(json_test
    PRIVATE main.cpp
    PUBLIC FILE_SET cxx_modules TYPE CXX_MODULES FILES json.cpp)

target_compile_features(json_test PUBLIC cxx_std_20)
target_include_directories(json_test PRIVATE ../../include)
