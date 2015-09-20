cmake_minimum_required(VERSION 3.0.0)

project(json CXX)

set (json_VERSION "1.0.0-rc1")

add_executable(json_unit
    src/json.hpp test/catch.hpp test/unit.cpp
)

if ("${CMAKE_CXX_COMPILER_ID}" MATCHES "Clang")
  set(CMAKE_CXX_FLAGS "-std=c++11 -stdlib=libc++")

elseif ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
    set(CMAKE_CXX_FLAGS "-std=c++11")

elseif ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "MSVC")
  set(CMAKE_CXX_FLAGS "/EHsc")

  STRING(REPLACE "/O2" "/Od" CMAKE_CXX_FLAGS_RELEASE ${CMAKE_CXX_FLAGS_RELEASE})

  add_definitions(-D_SCL_SECURE_NO_WARNINGS)
endif()

include_directories(
    src test
)

install(DIRECTORY ${CMAKE_CURRENT_LIST_DIR}/src/ DESTINATION include/nlohmann
        FILES_MATCHING PATTERN "*.[ih]pp")

include(CMakePackageConfigHelpers)
set(INCLUDE_INSTALL_DIR include/)
set(DEFINITIONS "${CMAKE_CXX_FLAGS}")
configure_package_config_file(
  ${CMAKE_CURRENT_LIST_DIR}/cmake/modules/nlohmann-json-config.cmake.in
  ${CMAKE_CURRENT_BINARY_DIR}/nlohmann-json-config.cmake
  INSTALL_DESTINATION lib/cmake/nlohmann-json-${json_VERSION}
  PATH_VARS INCLUDE_INSTALL_DIR)

write_basic_package_version_file(
    ${CMAKE_CURRENT_BINARY_DIR}/nlohmann-json-config-version.cmake
    VERSION ${json_VERSION}
    COMPATIBILITY AnyNewerVersion)

install(FILES
    ${CMAKE_CURRENT_BINARY_DIR}/nlohmann-json-config.cmake
    ${CMAKE_CURRENT_BINARY_DIR}/nlohmann-json-config-version.cmake
    DESTINATION lib/cmake/nlohmann-json-${json_VERSION})
