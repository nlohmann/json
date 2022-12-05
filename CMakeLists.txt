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

add_library(nlohmann_json INTERFACE)
add_library(nlohmann_json::nlohmann_json ALIAS nlohmann_json)
if (${CMAKE_VERSION} VERSION_LESS "3.8.0")
    target_compile_features(nlohmann_json INTERFACE cxx_range_for)
else()
    target_compile_features(nlohmann_json INTERFACE cxx_std_11)
endif()

target_compile_definitions(
    nlohmann_json
    INTERFACE
    $<$<NOT:$<BOOL:${JSON_GlobalUDLs}>>:JSON_USE_GLOBAL_UDLS=0>
    $<$<NOT:$<BOOL:${JSON_ImplicitConversions}>>:JSON_USE_IMPLICIT_CONVERSIONS=0>
    $<$<BOOL:${JSON_DisableEnumSerialization}>:JSON_DISABLE_ENUM_SERIALIZATION=1>
    $<$<BOOL:${JSON_Diagnostics}>:JSON_DIAGNOSTICS=1>
    $<$<BOOL:${JSON_LegacyDiscardedValueComparison}>:JSON_USE_LEGACY_DISCARDED_VALUE_COMPARISON=1>
)

target_include_directories(
    nlohmann_json
    ${JSON_SYSTEM_INCLUDE} INTERFACE
    $<BUILD_INTERFACE:${JSON_BUILD_INCLUDE_DIR}>
    $<INSTALL_INTERFACE:${JSON_INSTALL_INCLUDE_DIR}>
)

# add Natvis debug view definition file for MSVC
if (MSVC)
    target_sources(
        nlohmann_json
        INTERFACE
            $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/nlohmann_json.natvis>
            $<INSTALL_INTERFACE:nlohmann_json.natvis>
    )
endif()

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
# generate package configuration files
#############################################################################

# generate pkg-config file
configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake/pkg-config.pc.in"
    "${CMAKE_CURRENT_BINARY_DIR}/nlohmann_json.pc"
)

include(CMakePackageConfigHelpers)

# generate CMake module configuration file
configure_package_config_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake/nlohmann_jsonConfig.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/nlohmann_jsonConfig.cmake"
    INSTALL_DESTINATION "${JSON_INSTALL_CONFIG_DIR}/cmake/nlohmann_json"
    NO_SET_AND_CHECK_MACRO
)

# generate CMake module version file
if(CMAKE_VERSION VERSION_EQUAL "3.14" OR CMAKE_VERSION VERSION_GREATER "3.14")
    write_basic_package_version_file(
        "${CMAKE_CURRENT_BINARY_DIR}/nlohmann_jsonConfigVersion.cmake"
        COMPATIBILITY SameMajorVersion
        ARCH_INDEPENDENT
    )
else()
    # use a custom package version config file instead of
    # write_basic_package_version_file to ensure that it's architecture-independent
    # https://github.com/nlohmann/json/issues/1697
    configure_file(
        "${CMAKE_CURRENT_SOURCE_DIR}/cmake/nlohmann_jsonConfigVersion.cmake.in"
        "${CMAKE_CURRENT_BINARY_DIR}/nlohmann_jsonConfigVersion.cmake"
        @ONLY
    )
endif()

# generate CMake module targets file for use without installation
export(
    TARGETS nlohmann_json
    NAMESPACE nlohmann_json::
    FILE "${CMAKE_CURRENT_BINARY_DIR}/nlohmann_jsonTargets.cmake"
)

#############################################################################
# install files and targets
#############################################################################

if(JSON_Install)
    # install pkg-config file
    install(
        FILES "${CMAKE_CURRENT_BINARY_DIR}/nlohmann_json.pc"
        DESTINATION "${JSON_INSTALL_CONFIG_DIR}/pkgconfig"
    )

    # install CMake module configuration and version files
    install(
        FILES "${CMAKE_CURRENT_BINARY_DIR}/nlohmann_jsonConfig.cmake"
              "${CMAKE_CURRENT_BINARY_DIR}/nlohmann_jsonConfigVersion.cmake"
        DESTINATION "${JSON_INSTALL_CONFIG_DIR}/cmake/nlohmann_json"
    )

    # install targets
    install(
        TARGETS nlohmann_json
        EXPORT nlohmann_jsonTargets
        INCLUDES DESTINATION "${JSON_INSTALL_INCLUDE_DIR}"
    )

    # generate and install CMake module targets file(s)
    install(
        EXPORT nlohmann_jsonTargets
        NAMESPACE nlohmann_json::
        DESTINATION "${JSON_INSTALL_CONFIG_DIR}/cmake/nlohmann_json"
    )

    # install header files
    install(
        DIRECTORY "${JSON_BUILD_INCLUDE_DIR}"
        DESTINATION "${JSON_INSTALL_INCLUDE_DIR}"
    )

    # install Natvis debug view definition file for MSVC
    if (MSVC)
        install(
            FILES "nlohmann_json.natvis"
            DESTINATION .
        )
    endif()
endif()

#############################################################################
# print feature summary
#############################################################################

include(json_summary)
