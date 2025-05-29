cmake_minimum_required(VERSION 3.28)

project(json_test CXX)

set(nlohmann_json_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../../build_modules)

find_package(nlohmann_json QUIET PATHS ${CMAKE_CURRENT_SOURCE_DIR}/../../build_modules NO_DEFAULT_PATH)

if(NOT nlohmann_json_FOUND)
    add_library(nlohmann_json INTERFACE)
    target_include_directories(nlohmann_json INTERFACE ../../include)
    add_library(nlohmann_json::nlohmann_json ALIAS nlohmann_json)
endif()

add_executable(json_test main.cpp)
target_link_libraries(json_test nlohmann_json::nlohmann_json)

target_compile_definitions(json_test 
    PRIVATE NLOHMANN_JSON_BUILD_MODULES
)

target_compile_features(json_test PUBLIC cxx_std_20)