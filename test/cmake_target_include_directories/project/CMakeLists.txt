cmake_minimum_required(VERSION 3.1)

project(DummyImport CXX)

add_executable(with_private_target main.cpp)
target_include_directories(with_private_target PRIVATE ${nlohmann_json_source}/include)
set_target_properties(with_private_target PROPERTIES CXX_STANDARD 11)

add_executable(with_private_system_target main.cpp)
target_include_directories(with_private_system_target PRIVATE SYSTEM ${nlohmann_json_source}/include)
set_target_properties(with_private_system_target PROPERTIES CXX_STANDARD 11)
