cmake_minimum_required(VERSION 3.1)

project(DummyImport CXX)

find_package(nlohmann_json REQUIRED)

add_executable(with_namespace_target main.cpp)
target_link_libraries(with_namespace_target nlohmann_json::nlohmann_json)

add_executable(without_namespace_target main.cpp)
target_link_libraries(without_namespace_target nlohmann_json)

