# Download and unpack googletest at configure time
set(GOOGLETEST_PREFIX "${benchmark_BINARY_DIR}/third_party/googletest")
configure_file(${benchmark_SOURCE_DIR}/cmake/GoogleTest.cmake.in ${GOOGLETEST_PREFIX}/CMakeLists.txt @ONLY)

set(GOOGLETEST_PATH "${CMAKE_CURRENT_SOURCE_DIR}/googletest" CACHE PATH "") # Mind the quotes
execute_process(COMMAND ${CMAKE_COMMAND} -G "${CMAKE_GENERATOR}"
  -DALLOW_DOWNLOADING_GOOGLETEST=${BENCHMARK_DOWNLOAD_DEPENDENCIES} -DGOOGLETEST_PATH:PATH=${GOOGLETEST_PATH} .
  RESULT_VARIABLE result
  WORKING_DIRECTORY ${GOOGLETEST_PREFIX}
)

if(result)
  message(FATAL_ERROR "CMake step for googletest failed: ${result}")
endif()

execute_process(
  COMMAND ${CMAKE_COMMAND} --build .
  RESULT_VARIABLE result
  WORKING_DIRECTORY ${GOOGLETEST_PREFIX}
)

if(result)
  message(FATAL_ERROR "Build step for googletest failed: ${result}")
endif()

# Prevent overriding the parent project's compiler/linker
# settings on Windows
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)

include(${GOOGLETEST_PREFIX}/googletest-paths.cmake)

# Add googletest directly to our build. This defines
# the gtest and gtest_main targets.
add_subdirectory(${GOOGLETEST_SOURCE_DIR}
                 ${GOOGLETEST_BINARY_DIR}
                 EXCLUDE_FROM_ALL)

set_target_properties(gtest PROPERTIES INTERFACE_SYSTEM_INCLUDE_DIRECTORIES $<TARGET_PROPERTY:gtest,INTERFACE_INCLUDE_DIRECTORIES>)
set_target_properties(gtest_main PROPERTIES INTERFACE_SYSTEM_INCLUDE_DIRECTORIES $<TARGET_PROPERTY:gtest_main,INTERFACE_INCLUDE_DIRECTORIES>)
set_target_properties(gmock PROPERTIES INTERFACE_SYSTEM_INCLUDE_DIRECTORIES $<TARGET_PROPERTY:gmock,INTERFACE_INCLUDE_DIRECTORIES>)
set_target_properties(gmock_main PROPERTIES INTERFACE_SYSTEM_INCLUDE_DIRECTORIES $<TARGET_PROPERTY:gmock_main,INTERFACE_INCLUDE_DIRECTORIES>)
