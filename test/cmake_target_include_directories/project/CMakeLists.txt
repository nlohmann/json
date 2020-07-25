cmake_minimum_required(VERSION 3.1)

project(DummyImport CXX)

add_executable(with_private_target main.cpp)
target_include_directories(with_private_target PRIVATE ${nlohmann_json_source}/include)
set_target_properties(with_private_target PROPERTIES CXX_STANDARD 11)

add_executable(with_private_system_target main.cpp)
target_include_directories(with_private_system_target PRIVATE SYSTEM ${nlohmann_json_source}/include)
set_target_properties(with_private_system_target PROPERTIES CXX_STANDARD 11)

# regression from https://github.com/nlohmann/json/discussions/2281
add_library(Foo STATIC Foo.cpp Bar.cpp)
target_include_directories(Foo PUBLIC ${CMAKE_CURRENT_SOURCE_DIR} ${nlohmann_json_source}/include)
set_target_properties(Foo PROPERTIES CXX_STANDARD 11)

add_library(Bar STATIC Bar.cpp)
target_link_libraries(Bar PRIVATE Foo)
target_include_directories(Bar PUBLIC ${CMAKE_CURRENT_SOURCE_DIR} ${nlohmann_json_source}/include)
set_target_properties(Bar PROPERTIES CXX_STANDARD 11)
