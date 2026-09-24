cmake_minimum_required(VERSION 3.14)

project(DummyImport CXX)

include(FetchContent)

get_filename_component(GIT_REPOSITORY_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/../../.. ABSOLUTE)
FetchContent_Declare(json GIT_REPOSITORY ${GIT_REPOSITORY_DIRECTORY} GIT_TAG HEAD)
FetchContent_MakeAvailable(json)

if(MSVC)
    add_compile_options(/EHsc)
endif()

add_executable(with_namespace_target main.cpp)
target_link_libraries(with_namespace_target nlohmann_json::nlohmann_json)

add_executable(without_namespace_target main.cpp)
target_link_libraries(without_namespace_target nlohmann_json)
