cmake_minimum_required(VERSION 3.15)

include("cmake/HunterGate.cmake")
HunterGate(
    URL "https://github.com/cpp-pm/hunter/archive/v0.23.297.tar.gz"
    SHA1 "3319fe6a3b08090df7df98dee75134d68e2ef5a3"
)

project(json_example)

hunter_add_package(nlohmann_json)
find_package(nlohmann_json CONFIG REQUIRED)

add_executable(json_example example.cpp)
target_link_libraries(json_example PRIVATE nlohmann_json::nlohmann_json)
