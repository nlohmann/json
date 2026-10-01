cmake_minimum_required(VERSION 3.11...3.14)

project(DummyImport CXX)

include(FetchContent)

# This test deliberately covers the pre-3.14 FetchContent_Populate pattern
# (see FetchContent_MakeAvailable in ../../cmake_fetch_content2/project for
# the 3.14+ alternative), which CMake 3.30 deprecated as CMP0169. Silence the
# deprecation warning on purpose instead of switching to the new pattern.
if(POLICY CMP0169)
  cmake_policy(SET CMP0169 OLD)
endif()

get_filename_component(GIT_REPOSITORY_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/../../.. ABSOLUTE)
FetchContent_Declare(json GIT_REPOSITORY ${GIT_REPOSITORY_DIRECTORY} GIT_TAG HEAD)

FetchContent_GetProperties(json)
if(NOT json_POPULATED)
  FetchContent_Populate(json)
  add_subdirectory(${json_SOURCE_DIR} ${json_BINARY_DIR} EXCLUDE_FROM_ALL)
endif()

if(MSVC)
  add_compile_options(/EHsc)
endif()

add_executable(with_namespace_target main.cpp)
target_link_libraries(with_namespace_target nlohmann_json::nlohmann_json)

add_executable(without_namespace_target main.cpp)
target_link_libraries(without_namespace_target nlohmann_json)
