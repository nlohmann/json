project(json_example)
cmake_minimum_required(VERSION 2.8.12)

find_package(nlohmann_json CONFIG REQUIRED)

add_executable(json_example example.cpp)
target_link_libraries(json_example PRIVATE nlohmann_json::nlohmann_json)
