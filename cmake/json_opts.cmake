include(CMakeDependentOption)
include(GNUInstallDirs)

#############################################################################
# test options
#############################################################################

# VERSION_GREATER_EQUAL is not available in CMake 3.1
if(${JSON_MAIN_PROJECT} AND (${CMAKE_VERSION} VERSION_EQUAL 3.13 OR ${CMAKE_VERSION} VERSION_GREATER 3.13))
    set(JSON_BuildTests_INIT ON)
else()
    set(JSON_BuildTests_INIT OFF)
endif()
option(JSON_BuildTests "Build the unit tests when BUILD_TESTING is enabled." ${JSON_BuildTests_INIT})
set(JSON_32bitTest AUTO CACHE STRING "Enable the 32bit unit test (ON/OFF/AUTO/ONLY).")
cmake_dependent_option(JSON_FastTests "Skip expensive/slow tests." OFF "JSON_BuildTests" OFF)
set(JSON_TestDataDirectory "$ENV{JSON_TEST_DATA_DIRECTORY}" CACHE FILEPATH "Test data directory for the unit tests (will be downloaded if not specified).")
cmake_dependent_option(JSON_Valgrind "Execute test suite with Valgrind." OFF "JSON_BuildTests" OFF)

set(JSON_TestStandards "" CACHE STRING "The list of standards to test explicitly.")

#############################################################################
# CI options
#############################################################################

option(JSON_CI "Enable CI build targets." OFF)

#############################################################################
# build & install options
#############################################################################

option(JSON_Diagnostics "Use extended diagnostic messages." OFF)
option(JSON_DisableEnumSerialization "Disable default integer enum serialization." OFF)
option(JSON_GlobalUDLs "Place user-defined string literals in the global namespace." ON)
option(JSON_ImplicitConversions "Enable implicit conversions." ON)
option(JSON_LegacyDiscardedValueComparison "Enable legacy discarded value comparison." OFF)

option(JSON_Install "Install CMake targets during install step." ${JSON_MAIN_PROJECT})
option(JSON_MultipleHeaders "Use non-amalgamated version of the library." ON)
option(JSON_SystemInclude "Include as system headers (skip for clang-tidy)." OFF)

#############################################################################
# configuration
#############################################################################

set(JSON_TARGET_NAME                ${PROJECT_NAME})
set(JSON_CONFIG_INSTALL_DIR         "${CMAKE_INSTALL_DATADIR}/cmake/${PROJECT_NAME}" CACHE INTERNAL "")
set(JSON_INCLUDE_INSTALL_DIR        "${CMAKE_INSTALL_INCLUDEDIR}")
set(JSON_TARGETS_EXPORT_NAME        "${PROJECT_NAME}Targets")
set(JSON_CMAKE_CONFIG_TEMPLATE      "cmake/nlohmann_jsonConfig.cmake.in")
set(JSON_CMAKE_CONFIG_DIR           "${CMAKE_CURRENT_BINARY_DIR}")
set(JSON_CMAKE_VERSION_CONFIG_FILE  "${JSON_CMAKE_CONFIG_DIR}/${PROJECT_NAME}ConfigVersion.cmake")
set(JSON_CMAKE_PROJECT_CONFIG_FILE  "${JSON_CMAKE_CONFIG_DIR}/${PROJECT_NAME}Config.cmake")
set(JSON_CMAKE_PROJECT_TARGETS_FILE "${JSON_CMAKE_CONFIG_DIR}/${PROJECT_NAME}Targets.cmake")
set(JSON_PKGCONFIG_INSTALL_DIR      "${CMAKE_INSTALL_DATADIR}/pkgconfig")

if (JSON_MultipleHeaders)
    set(JSON_INCLUDE_BUILD_DIR "${PROJECT_SOURCE_DIR}/include/")
else()
    set(JSON_INCLUDE_BUILD_DIR "${PROJECT_SOURCE_DIR}/single_include/")
endif()

if (JSON_SystemInclude)
    set(JSON_SYSTEM_INCLUDE "SYSTEM")
endif()

set(JSON_TEST_DATA_URL     https://github.com/nlohmann/json_test_data.git)
set(JSON_TEST_DATA_VERSION 3.1.0)
