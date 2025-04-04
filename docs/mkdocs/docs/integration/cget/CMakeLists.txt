cmake_minimum_required(VERSION 3.15)
project(json_example)

find_package(nlohmann_json REQUIRED)

add_executable(json_example example.cpp)
target_link_libraries(json_example PRIVATE nlohmann_json::nlohmann_json)
