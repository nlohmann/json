cmake_minimum_required(VERSION 3.1)

#############################################################################
# set up
#############################################################################

# set policies
if (POLICY CMP0077)
    # Allow CMake 3.13+ to override options when using FetchContent / add_subdirectory.
    cmake_policy(SET CMP0077 NEW)
endif ()

# set the CMake module path
set(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake ${CMAKE_MODULE_PATH})

# determine if nlohmann_json is the main project or built as a subproject (using add_subdirectory)
set(JSON_MAIN_PROJECT OFF)
if (CMAKE_CURRENT_SOURCE_DIR STREQUAL CMAKE_SOURCE_DIR)
    set(JSON_MAIN_PROJECT ON)
endif()

# set project name and version
project(nlohmann_json VERSION 3.11.2 LANGUAGES CXX)

# print CMake, system, and compiler information
include(json_info)

# handle options and configuration
include(json_opts)

#############################################################################
# add library targets
#############################################################################

add_library(${JSON_TARGET_NAME} INTERFACE)
add_library(${PROJECT_NAME}::${JSON_TARGET_NAME} ALIAS ${JSON_TARGET_NAME})
if (${CMAKE_VERSION} VERSION_LESS "3.8.0")
    target_compile_features(${JSON_TARGET_NAME} INTERFACE cxx_range_for)
else()
    target_compile_features(${JSON_TARGET_NAME} INTERFACE cxx_std_11)
endif()

target_compile_definitions(
    ${JSON_TARGET_NAME}
    INTERFACE
    $<$<NOT:$<BOOL:${JSON_GlobalUDLs}>>:JSON_USE_GLOBAL_UDLS=0>
    $<$<NOT:$<BOOL:${JSON_ImplicitConversions}>>:JSON_USE_IMPLICIT_CONVERSIONS=0>
    $<$<BOOL:${JSON_DisableEnumSerialization}>:JSON_DISABLE_ENUM_SERIALIZATION=1>
    $<$<BOOL:${JSON_Diagnostics}>:JSON_DIAGNOSTICS=1>
    $<$<BOOL:${JSON_LegacyDiscardedValueComparison}>:JSON_USE_LEGACY_DISCARDED_VALUE_COMPARISON=1>
)

target_include_directories(
    ${JSON_TARGET_NAME}
    ${JSON_SYSTEM_INCLUDE} INTERFACE
    $<BUILD_INTERFACE:${JSON_INCLUDE_BUILD_DIR}>
    $<INSTALL_INTERFACE:include>
)

## add debug view definition file for msvc (natvis)
if (MSVC)
    set(NLOHMANN_ADD_NATVIS TRUE)
    set(NLOHMANN_NATVIS_FILE "nlohmann_json.natvis")
    target_sources(
        ${JSON_TARGET_NAME}
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

#############################################################################
# add tests
#############################################################################

if (JSON_BuildTests)
    include(CTest)
    enable_testing()
    add_subdirectory(tests)
endif()

# add CI targets
if(JSON_CI)
    include(json_ci)
endif()

#############################################################################
# install files and targets
#############################################################################

include(CMakePackageConfigHelpers)
# use a custom package version config file instead of
# write_basic_package_version_file to ensure that it's architecture-independent
# https://github.com/nlohmann/json/issues/1697
configure_file(
    "cmake/nlohmann_jsonConfigVersion.cmake.in"
    ${JSON_CMAKE_VERSION_CONFIG_FILE}
    @ONLY
)
configure_file(
    ${JSON_CMAKE_CONFIG_TEMPLATE}
    ${JSON_CMAKE_PROJECT_CONFIG_FILE}
    @ONLY
)

if(JSON_Install)
    install(
        DIRECTORY ${JSON_INCLUDE_BUILD_DIR}
        DESTINATION ${JSON_INCLUDE_INSTALL_DIR}
    )
    install(
        FILES ${JSON_CMAKE_PROJECT_CONFIG_FILE} ${JSON_CMAKE_VERSION_CONFIG_FILE}
        DESTINATION ${JSON_CONFIG_INSTALL_DIR}
    )
    if (NLOHMANN_ADD_NATVIS)
        install(
            FILES ${NLOHMANN_NATVIS_FILE}
            DESTINATION .
    )
    endif()
    export(
        TARGETS ${JSON_TARGET_NAME}
        NAMESPACE ${PROJECT_NAME}::
        FILE ${JSON_CMAKE_PROJECT_TARGETS_FILE}
    )
    install(
        TARGETS ${JSON_TARGET_NAME}
        EXPORT ${JSON_TARGETS_EXPORT_NAME}
        INCLUDES DESTINATION ${JSON_INCLUDE_INSTALL_DIR}
    )
    install(
        EXPORT ${JSON_TARGETS_EXPORT_NAME}
        NAMESPACE ${PROJECT_NAME}::
        DESTINATION ${JSON_CONFIG_INSTALL_DIR}
    )
    install(
        FILES "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}.pc"
        DESTINATION ${JSON_PKGCONFIG_INSTALL_DIR}
    )
endif()

#############################################################################
# print feature summary
#############################################################################

include(json_summary)
