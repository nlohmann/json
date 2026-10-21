cmake_minimum_required(VERSION 3.15)

include("cmake/HunterGate.cmake")
HunterGate(
    URL "https://github.com/cpp-pm/hunter/archive/v0.26.12.tar.gz"
    SHA1 "6498c5d0dec25d7fffb2b0574ebaf265179b894d"
)

project(json_example)

hunter_add_package(nlohmann_json)
find_package(nlohmann_json CONFIG REQUIRED)

add_executable(json_example example.cpp)
target_link_libraries(json_example PRIVATE nlohmann_json::nlohmann_json)
