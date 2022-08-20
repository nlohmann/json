cmake_minimum_required(VERSION 3.11)

project(DummyImport CXX)

include(FetchContent)

set(FETCHCONTENT_QUIET OFF)
message(WARNING "CMAKE_CURRENT_SOURCE_DIR = ${CMAKE_CURRENT_SOURCE_DIR}")
message(WARNING "CMAKE_SOURCE_DIR         = ${CMAKE_SOURCE_DIR}")
message(WARNING "CMAKE_CURRENT_BINARY_DIR = ${CMAKE_CURRENT_BINARY_DIR}")
message(WARNING "CMAKE_BINARY_DIR         = ${CMAKE_BINARY_DIR}")
get_filename_component(GIT_REPOSITORY_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/../../.. ABSOLUTE)
message(WARNING "GIT_REPOSITORY_DIRECTORY = ${GIT_REPOSITORY_DIRECTORY}")
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
