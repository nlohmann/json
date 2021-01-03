cmake_minimum_required(VERSION 3.11...3.14)

project(DummyImport CXX)

include(FetchContent)

get_filename_component(GIT_REPOSITORY_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/../../.. ABSOLUTE)
FetchContent_Declare(json GIT_REPOSITORY ${GIT_REPOSITORY_DIRECTORY} GIT_TAG HEAD)

FetchContent_GetProperties(json)
if(NOT json_POPULATED)
  FetchContent_Populate(json)
  add_subdirectory(${json_SOURCE_DIR} ${json_BINARY_DIR} EXCLUDE_FROM_ALL)
endif()

add_executable(with_namespace_target main.cpp)
target_link_libraries(with_namespace_target nlohmann_json::nlohmann_json)

add_executable(without_namespace_target main.cpp)
target_link_libraries(without_namespace_target nlohmann_json)
