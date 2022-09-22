include(CMakeDependentOption)

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

set(NLOHMANN_JSON_TARGET_NAME                ${PROJECT_NAME})
set(NLOHMANN_JSON_CONFIG_INSTALL_DIR         "${CMAKE_INSTALL_DATADIR}/cmake/${PROJECT_NAME}" CACHE INTERNAL "")
set(NLOHMANN_JSON_INCLUDE_INSTALL_DIR        "${CMAKE_INSTALL_INCLUDEDIR}")
set(NLOHMANN_JSON_TARGETS_EXPORT_NAME        "${PROJECT_NAME}Targets")
set(NLOHMANN_JSON_CMAKE_CONFIG_TEMPLATE      "cmake/config.cmake.in")
set(NLOHMANN_JSON_CMAKE_CONFIG_DIR           "${CMAKE_CURRENT_BINARY_DIR}")
set(NLOHMANN_JSON_CMAKE_VERSION_CONFIG_FILE  "${NLOHMANN_JSON_CMAKE_CONFIG_DIR}/${PROJECT_NAME}ConfigVersion.cmake")
set(NLOHMANN_JSON_CMAKE_PROJECT_CONFIG_FILE  "${NLOHMANN_JSON_CMAKE_CONFIG_DIR}/${PROJECT_NAME}Config.cmake")
set(NLOHMANN_JSON_CMAKE_PROJECT_TARGETS_FILE "${NLOHMANN_JSON_CMAKE_CONFIG_DIR}/${PROJECT_NAME}Targets.cmake")
set(NLOHMANN_JSON_PKGCONFIG_INSTALL_DIR      "${CMAKE_INSTALL_DATADIR}/pkgconfig")

if (JSON_MultipleHeaders)
    set(NLOHMANN_JSON_INCLUDE_BUILD_DIR "${PROJECT_SOURCE_DIR}/include/")
else()
    set(NLOHMANN_JSON_INCLUDE_BUILD_DIR "${PROJECT_SOURCE_DIR}/single_include/")
endif()

if (JSON_SystemInclude)
    set(NLOHMANN_JSON_SYSTEM_INCLUDE "SYSTEM")
endif()
