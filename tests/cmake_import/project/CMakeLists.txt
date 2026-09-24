cmake_minimum_required(VERSION 3.5...3.14)

project(DummyImport CXX)

find_package(nlohmann_json REQUIRED)

if(MSVC)
    add_compile_options(/EHsc)
endif()

add_executable(with_namespace_target main.cpp)
target_link_libraries(with_namespace_target nlohmann_json::nlohmann_json)

add_executable(without_namespace_target main.cpp)
target_link_libraries(without_namespace_target nlohmann_json)
