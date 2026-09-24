cmake_minimum_required(VERSION 3.5...3.14)

project(DummyImport CXX)

if(MSVC)
    add_compile_options(/EHsc)
endif()

set(JSON_BuildTests OFF CACHE INTERNAL "")
add_subdirectory(${nlohmann_json_source}
   ${CMAKE_CURRENT_BINARY_DIR}/nlohmann_json)

add_executable(with_namespace_target main.cpp)
target_link_libraries(with_namespace_target nlohmann_json::nlohmann_json)

add_executable(without_namespace_target main.cpp)
target_link_libraries(without_namespace_target nlohmann_json)

if(NOT MSVC)
    add_executable(without_exceptions main.cpp)
    target_link_libraries(without_exceptions nlohmann_json::nlohmann_json)
    target_compile_definitions(without_exceptions PRIVATE JSON_NOEXCEPTION)
    target_compile_options(without_exceptions PRIVATE -fno-exceptions)
endif()
