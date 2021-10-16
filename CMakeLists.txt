cmake_minimum_required(VERSION 3.1)

##
## PROJECT
## name and version
##
project(nlohmann_json VERSION 3.10.4 LANGUAGES CXX)

##
## MAIN_PROJECT CHECK
## determine if nlohmann_json is built as a subproject (using add_subdirectory) or if it is the main project
##
set(MAIN_PROJECT OFF)
if (CMAKE_CURRENT_SOURCE_DIR STREQUAL CMAKE_SOURCE_DIR)
    set(MAIN_PROJECT ON)
endif()

##
## INCLUDE
##
##
include(ExternalProject)

##
## OPTIONS
##

if (POLICY CMP0077)
    # Allow CMake 3.13+ to override options when using FetchContent / add_subdirectory.
    cmake_policy(SET CMP0077 NEW)
endif ()

option(JSON_BuildTests          "Build the unit tests when BUILD_TESTING is enabled." ${MAIN_PROJECT})
option(JSON_CI                  "Enable CI build targets." OFF)
option(JSON_Diagnostics         "Use extended diagnostic messages." OFF)
option(JSON_ImplicitConversions "Enable implicit conversions." ON)
option(JSON_Install             "Install CMake targets during install step." ${MAIN_PROJECT})
option(JSON_MultipleHeaders     "Use non-amalgamated version of the library." OFF)
option(JSON_SystemInclude       "Include as system headers (skip for clang-tidy)." OFF)

if (JSON_CI)
    include(cmake/ci.cmake)
endif ()

##
## CONFIGURATION
##
include(GNUInstallDirs)

set(NLOHMANN_JSON_TARGET_NAME               ${PROJECT_NAME})
set(NLOHMANN_JSON_CONFIG_INSTALL_DIR        "${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME}" CACHE INTERNAL "")
set(NLOHMANN_JSON_INCLUDE_INSTALL_DIR       "${CMAKE_INSTALL_INCLUDEDIR}")
set(NLOHMANN_JSON_TARGETS_EXPORT_NAME       "${PROJECT_NAME}Targets")
set(NLOHMANN_JSON_CMAKE_CONFIG_TEMPLATE     "cmake/config.cmake.in")
set(NLOHMANN_JSON_CMAKE_CONFIG_DIR          "${CMAKE_CURRENT_BINARY_DIR}")
set(NLOHMANN_JSON_CMAKE_VERSION_CONFIG_FILE "${NLOHMANN_JSON_CMAKE_CONFIG_DIR}/${PROJECT_NAME}ConfigVersion.cmake")
set(NLOHMANN_JSON_CMAKE_PROJECT_CONFIG_FILE "${NLOHMANN_JSON_CMAKE_CONFIG_DIR}/${PROJECT_NAME}Config.cmake")
set(NLOHMANN_JSON_CMAKE_PROJECT_TARGETS_FILE "${NLOHMANN_JSON_CMAKE_CONFIG_DIR}/${PROJECT_NAME}Targets.cmake")
set(NLOHMANN_JSON_PKGCONFIG_INSTALL_DIR     "${CMAKE_INSTALL_LIBDIR}/pkgconfig")

if (JSON_MultipleHeaders)
    set(NLOHMANN_JSON_INCLUDE_BUILD_DIR "${PROJECT_SOURCE_DIR}/include/")
    message(STATUS "Using the multi-header code from ${NLOHMANN_JSON_INCLUDE_BUILD_DIR}")
else()
    set(NLOHMANN_JSON_INCLUDE_BUILD_DIR "${PROJECT_SOURCE_DIR}/single_include/")
    message(STATUS "Using the single-header code from ${NLOHMANN_JSON_INCLUDE_BUILD_DIR}")
endif()

if (NOT JSON_ImplicitConversions)
    message(STATUS "Implicit conversions are disabled")
endif()

if (JSON_Diagnostics)
    message(STATUS "Diagnostics enabled")
endif()

if (JSON_SystemInclude)
    set(NLOHMANN_JSON_SYSTEM_INCLUDE "SYSTEM")
endif()

##
## TARGET
## create target and add include path
##
add_library(${NLOHMANN_JSON_TARGET_NAME} INTERFACE)
add_library(${PROJECT_NAME}::${NLOHMANN_JSON_TARGET_NAME} ALIAS ${NLOHMANN_JSON_TARGET_NAME})
if (${CMAKE_VERSION} VERSION_LESS "3.8.0")
    target_compile_features(${NLOHMANN_JSON_TARGET_NAME} INTERFACE cxx_range_for)
else()
    target_compile_features(${NLOHMANN_JSON_TARGET_NAME} INTERFACE cxx_std_11)
endif()

target_compile_definitions(
    ${NLOHMANN_JSON_TARGET_NAME}
    INTERFACE
    JSON_USE_IMPLICIT_CONVERSIONS=$<BOOL:${JSON_ImplicitConversions}>
    JSON_DIAGNOSTICS=$<BOOL:${JSON_Diagnostics}>
)

target_include_directories(
    ${NLOHMANN_JSON_TARGET_NAME}
    ${NLOHMANN_JSON_SYSTEM_INCLUDE} INTERFACE
    $<BUILD_INTERFACE:${NLOHMANN_JSON_INCLUDE_BUILD_DIR}>
    $<INSTALL_INTERFACE:include>
)

## add debug view definition file for msvc (natvis)
if (MSVC)
    set(NLOHMANN_ADD_NATVIS TRUE)
    set(NLOHMANN_NATVIS_FILE "nlohmann_json.natvis")
    target_sources(
        ${NLOHMANN_JSON_TARGET_NAME}
        INTERFACE
            $<INSTALL_INTERFACE:${NLOHMANN_NATVIS_FILE}>
            $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/${NLOHMANN_NATVIS_FILE}>
    )
endif()

# Install a pkg-config file, so other tools can find this.
CONFIGURE_FILE(
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake/pkg-config.pc.in"
    "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}.pc"
)

##
## TESTS
## create and configure the unit test target
##
if (JSON_BuildTests)
    include(CTest)
    enable_testing()
    add_subdirectory(test)
endif()

##
## INSTALL
## install header files, generate and install cmake config files for find_package()
##
include(CMakePackageConfigHelpers)
# use a custom package version config file instead of
# write_basic_package_version_file to ensure that it's architecture-independent
# https://github.com/nlohmann/json/issues/1697
configure_file(
    "cmake/nlohmann_jsonConfigVersion.cmake.in"
    ${NLOHMANN_JSON_CMAKE_VERSION_CONFIG_FILE}
    @ONLY
)
configure_file(
    ${NLOHMANN_JSON_CMAKE_CONFIG_TEMPLATE}
    ${NLOHMANN_JSON_CMAKE_PROJECT_CONFIG_FILE}
    @ONLY
)

if(JSON_Install)
    install(
        DIRECTORY ${NLOHMANN_JSON_INCLUDE_BUILD_DIR}
        DESTINATION ${NLOHMANN_JSON_INCLUDE_INSTALL_DIR}
    )
    install(
        FILES ${NLOHMANN_JSON_CMAKE_PROJECT_CONFIG_FILE} ${NLOHMANN_JSON_CMAKE_VERSION_CONFIG_FILE}
        DESTINATION ${NLOHMANN_JSON_CONFIG_INSTALL_DIR}
    )
    if (NLOHMANN_ADD_NATVIS)
        install(
            FILES ${NLOHMANN_NATVIS_FILE}
            DESTINATION .
    )
    endif()
    export(
        TARGETS ${NLOHMANN_JSON_TARGET_NAME}
        NAMESPACE ${PROJECT_NAME}::
        FILE ${NLOHMANN_JSON_CMAKE_PROJECT_TARGETS_FILE}
    )
    install(
        TARGETS ${NLOHMANN_JSON_TARGET_NAME}
        EXPORT ${NLOHMANN_JSON_TARGETS_EXPORT_NAME}
        INCLUDES DESTINATION ${NLOHMANN_JSON_INCLUDE_INSTALL_DIR}
    )
    install(
        EXPORT ${NLOHMANN_JSON_TARGETS_EXPORT_NAME}
        NAMESPACE ${PROJECT_NAME}::
        DESTINATION ${NLOHMANN_JSON_CONFIG_INSTALL_DIR}
    )
    install(
        FILES "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}.pc"
        DESTINATION ${NLOHMANN_JSON_PKGCONFIG_INSTALL_DIR}
    )
endif()
