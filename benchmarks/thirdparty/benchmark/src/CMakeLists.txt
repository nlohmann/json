# Allow the source files to find headers in src/
include(GNUInstallDirs)
include_directories(${PROJECT_SOURCE_DIR}/src)

if (DEFINED BENCHMARK_CXX_LINKER_FLAGS)
  list(APPEND CMAKE_SHARED_LINKER_FLAGS ${BENCHMARK_CXX_LINKER_FLAGS})
  list(APPEND CMAKE_MODULE_LINKER_FLAGS ${BENCHMARK_CXX_LINKER_FLAGS})
endif()

file(GLOB
  SOURCE_FILES
    *.cc
    ${PROJECT_SOURCE_DIR}/include/benchmark/*.h
    ${CMAKE_CURRENT_SOURCE_DIR}/*.h)
file(GLOB BENCHMARK_MAIN "benchmark_main.cc")
foreach(item ${BENCHMARK_MAIN})
  list(REMOVE_ITEM SOURCE_FILES "${item}")
endforeach()

add_library(benchmark ${SOURCE_FILES})
add_library(benchmark::benchmark ALIAS benchmark)
set_target_properties(benchmark PROPERTIES
  OUTPUT_NAME "benchmark"
  VERSION ${GENERIC_LIB_VERSION}
  SOVERSION ${GENERIC_LIB_SOVERSION}
)
target_include_directories(benchmark PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../include>
    )

# Link threads.
target_link_libraries(benchmark  ${BENCHMARK_CXX_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT})
find_library(LIBRT rt)
if(LIBRT)
  target_link_libraries(benchmark ${LIBRT})
endif()

if(CMAKE_BUILD_TYPE)
  string(TOUPPER ${CMAKE_BUILD_TYPE} CMAKE_BUILD_TYPE_UPPER)
endif()
if(NOT CMAKE_THREAD_LIBS_INIT AND "${CMAKE_CXX_FLAGS} ${CMAKE_CXX_FLAGS_${CMAKE_BUILD_TYPE_UPPER}}" MATCHES ".*-fsanitize=[^ ]*address.*")
  message(WARNING "CMake's FindThreads.cmake did not fail, but CMAKE_THREAD_LIBS_INIT ended up being empty. This was fixed in https://github.com/Kitware/CMake/commit/d53317130e84898c5328c237186dbd995aaf1c12 Let's guess that -pthread is sufficient.")
  target_link_libraries(benchmark -pthread)
endif()

# We need extra libraries on Windows
if(${CMAKE_SYSTEM_NAME} MATCHES "Windows")
  target_link_libraries(benchmark shlwapi)
endif()

# We need extra libraries on Solaris
if(${CMAKE_SYSTEM_NAME} MATCHES "SunOS")
  target_link_libraries(benchmark kstat)
endif()

# Benchmark main library
add_library(benchmark_main "benchmark_main.cc")
add_library(benchmark::benchmark_main ALIAS benchmark_main)
set_target_properties(benchmark_main PROPERTIES
  OUTPUT_NAME "benchmark_main"
  VERSION ${GENERIC_LIB_VERSION}
  SOVERSION ${GENERIC_LIB_SOVERSION}
)
target_include_directories(benchmark PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../include>
    )
target_link_libraries(benchmark_main benchmark::benchmark)


set(generated_dir "${CMAKE_CURRENT_BINARY_DIR}/generated")

set(version_config "${generated_dir}/${PROJECT_NAME}ConfigVersion.cmake")
set(project_config "${generated_dir}/${PROJECT_NAME}Config.cmake")
set(pkg_config "${generated_dir}/${PROJECT_NAME}.pc")
set(targets_export_name "${PROJECT_NAME}Targets")

set(namespace "${PROJECT_NAME}::")

include(CMakePackageConfigHelpers)
write_basic_package_version_file(
  "${version_config}" VERSION ${GENERIC_LIB_VERSION} COMPATIBILITY SameMajorVersion
)

configure_file("${PROJECT_SOURCE_DIR}/cmake/Config.cmake.in" "${project_config}" @ONLY)
configure_file("${PROJECT_SOURCE_DIR}/cmake/benchmark.pc.in" "${pkg_config}" @ONLY)

if (BENCHMARK_ENABLE_INSTALL)
  # Install target (will install the library to specified CMAKE_INSTALL_PREFIX variable)
  install(
    TARGETS benchmark benchmark_main
    EXPORT ${targets_export_name}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

  install(
    DIRECTORY "${PROJECT_SOURCE_DIR}/include/benchmark"
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
    FILES_MATCHING PATTERN "*.*h")

  install(
      FILES "${project_config}" "${version_config}"
      DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME}")

  install(
      FILES "${pkg_config}"
      DESTINATION "${CMAKE_INSTALL_LIBDIR}/pkgconfig")

  install(
      EXPORT "${targets_export_name}"
      NAMESPACE "${namespace}"
      DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME}")
endif()
