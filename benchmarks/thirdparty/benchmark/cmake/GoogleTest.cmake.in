cmake_minimum_required(VERSION 2.8.12)

project(googletest-download NONE)

# Enable ExternalProject CMake module
include(ExternalProject)

option(ALLOW_DOWNLOADING_GOOGLETEST "If googletest src tree is not found in location specified by GOOGLETEST_PATH, do fetch the archive from internet" OFF)
set(GOOGLETEST_PATH "/usr/src/googletest" CACHE PATH
                    "Path to the googletest root tree. Should contain googletest and googlemock subdirs. And CMakeLists.txt in root, and in both of these subdirs")

# Download and install GoogleTest

message(STATUS "Looking for Google Test sources")
message(STATUS "Looking for Google Test sources in ${GOOGLETEST_PATH}")
if(EXISTS "${GOOGLETEST_PATH}"            AND IS_DIRECTORY "${GOOGLETEST_PATH}"            AND EXISTS "${GOOGLETEST_PATH}/CMakeLists.txt" AND
   EXISTS "${GOOGLETEST_PATH}/googletest" AND IS_DIRECTORY "${GOOGLETEST_PATH}/googletest" AND EXISTS "${GOOGLETEST_PATH}/googletest/CMakeLists.txt" AND
   EXISTS "${GOOGLETEST_PATH}/googlemock" AND IS_DIRECTORY "${GOOGLETEST_PATH}/googlemock" AND EXISTS "${GOOGLETEST_PATH}/googlemock/CMakeLists.txt")
  message(STATUS "Found Google Test in ${GOOGLETEST_PATH}")

  ExternalProject_Add(
    googletest
    PREFIX            "${CMAKE_BINARY_DIR}"
    DOWNLOAD_DIR      "${CMAKE_BINARY_DIR}/download"
    SOURCE_DIR        "${GOOGLETEST_PATH}" # use existing src dir.
    BINARY_DIR        "${CMAKE_BINARY_DIR}/build"
    CONFIGURE_COMMAND ""
    BUILD_COMMAND     ""
    INSTALL_COMMAND   ""
    TEST_COMMAND      ""
  )
else()
  if(NOT ALLOW_DOWNLOADING_GOOGLETEST)
    message(SEND_ERROR "Did not find Google Test sources! Either pass correct path in GOOGLETEST_PATH, or enable BENCHMARK_DOWNLOAD_DEPENDENCIES, or disable BENCHMARK_ENABLE_GTEST_TESTS / BENCHMARK_ENABLE_TESTING.")
  else()
    message(WARNING "Did not find Google Test sources! Fetching from web...")
    ExternalProject_Add(
      googletest
      GIT_REPOSITORY    https://github.com/google/googletest.git
      GIT_TAG           master
      PREFIX            "${CMAKE_BINARY_DIR}"
      STAMP_DIR         "${CMAKE_BINARY_DIR}/stamp"
      DOWNLOAD_DIR      "${CMAKE_BINARY_DIR}/download"
      SOURCE_DIR        "${CMAKE_BINARY_DIR}/src"
      BINARY_DIR        "${CMAKE_BINARY_DIR}/build"
      CONFIGURE_COMMAND ""
      BUILD_COMMAND     ""
      INSTALL_COMMAND   ""
      TEST_COMMAND      ""
    )
  endif()
endif()

ExternalProject_Get_Property(googletest SOURCE_DIR BINARY_DIR)
file(WRITE googletest-paths.cmake
"set(GOOGLETEST_SOURCE_DIR \"${SOURCE_DIR}\")
set(GOOGLETEST_BINARY_DIR \"${BINARY_DIR}\")
")
