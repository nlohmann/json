cmake_minimum_required(VERSION 2.8.4)
project(json)

# Enable C++11 and set flags for coverage testing
SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -g -O0 --coverage -fprofile-arcs -ftest-coverage")

# Make everything public for testing purposes
add_definitions(-Dprivate=public)

# If not specified, use Debug as build type (necessary for coverage testing)
if( NOT CMAKE_BUILD_TYPE )
  set( CMAKE_BUILD_TYPE Debug CACHE STRING
       ""
       FORCE )
endif()

# CMake addons for lcov
# Only possible with g++ at the moment. We run otherwise just the test
if(CMAKE_COMPILER_IS_GNUCXX)
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -O0 --coverage -fprofile-arcs -ftest-coverage")
  set(CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/CMakeModules)
  include(CodeCoverage)

  setup_coverage(coverage)
endif()

# Normal sources
include_directories(src/)
aux_source_directory(src/ json_list)
add_library(json ${json_list})

# Testing
enable_testing()

# Search all test files in the test directory with a .cc suffix
file(GLOB TEST_FILES "test/*.cc")
foreach(TEST_FILE ${TEST_FILES})
  # We use the basename to identify the test. E.g "json_unit" for "json_unit.cc"
  get_filename_component(BASENAME ${TEST_FILE} NAME_WE)
  # Create a test executable
  add_executable(${BASENAME} ${TEST_FILE})
  # Link it with our main json file
  target_link_libraries(${BASENAME} json)

  # Add test if people want to use ctest
  add_test(${BASENAME} ${BASENAME})

  # If we are using g++, we also need to setup the commands for coverage
  # testing
  if(CMAKE_COMPILER_IS_GNUCXX)
    # Add a run_XXX target that runs the executable and produces the
    # coverage data automatically
    add_custom_target(run_${BASENAME} COMMAND ./${BASENAME})
    # Make sure that running requires the executable to be build
    add_dependencies (run_${BASENAME} ${BASENAME})
    # To create a valid coverage report, the executable has to be
    # executed first
    add_dependencies (coverage run_${BASENAME})
  endif()
endforeach()

