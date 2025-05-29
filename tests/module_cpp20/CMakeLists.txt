cmake_minimum_required(VERSION 3.28)

project(json_test CXX)

find_package(nlohmann_json REQUIRED)

add_executable(json_test main.cpp)
target_link_libraries(json_test nlohmann_json::nlohmann_json)

target_compile_definitions(json_test 
    PRIVATE NLOHMANN_JSON_BUILD_MODULES
)

target_compile_features(json_test PUBLIC cxx_std_20)
target_include_directories(json_test PRIVATE ../../include)
