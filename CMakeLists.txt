cmake_minimum_required(VERSION 3.1)

##
## PROJECT
## name and version
##
project(nlohmann_json VERSION 3.6.1 LANGUAGES CXX)

##
## INCLUDE
##
##
include(ExternalProject)

##
## OPTIONS
##
option(JSON_BuildTests "Build the unit tests when BUILD_TESTING is enabled." ON)
option(JSON_Install "Install CMake targets during install step." ON)
option(JSON_MultipleHeaders "Use non-amalgamated version of the library." OFF)

##
## CONFIGURATION
##
set(NLOHMANN_JSON_TARGET_NAME               ${PROJECT_NAME})
set(NLOHMANN_JSON_CONFIG_INSTALL_DIR        "lib/cmake/${PROJECT_NAME}"
  CACHE INTERNAL "")
set(NLOHMANN_JSON_INCLUDE_INSTALL_DIR       "include")
set(NLOHMANN_JSON_TARGETS_EXPORT_NAME       "${PROJECT_NAME}Targets")
set(NLOHMANN_JSON_CMAKE_CONFIG_TEMPLATE     "cmake/config.cmake.in")
set(NLOHMANN_JSON_CMAKE_CONFIG_DIR          "${CMAKE_CURRENT_BINARY_DIR}")
set(NLOHMANN_JSON_CMAKE_VERSION_CONFIG_FILE "${NLOHMANN_JSON_CMAKE_CONFIG_DIR}/${PROJECT_NAME}ConfigVersion.cmake")
set(NLOHMANN_JSON_CMAKE_PROJECT_CONFIG_FILE "${NLOHMANN_JSON_CMAKE_CONFIG_DIR}/${PROJECT_NAME}Config.cmake")
set(NLOHMANN_JSON_CMAKE_PROJECT_TARGETS_FILE "${NLOHMANN_JSON_CMAKE_CONFIG_DIR}/${PROJECT_NAME}Targets.cmake")

if (JSON_MultipleHeaders)
    set(NLOHMANN_JSON_INCLUDE_BUILD_DIR "${PROJECT_SOURCE_DIR}/include/")
    message(STATUS "Using the multi-header code from ${NLOHMANN_JSON_INCLUDE_BUILD_DIR}")
else()
    set(NLOHMANN_JSON_INCLUDE_BUILD_DIR "${PROJECT_SOURCE_DIR}/single_include/")
    message(STATUS "Using the single-header code from ${NLOHMANN_JSON_INCLUDE_BUILD_DIR}")
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

target_include_directories(
    ${NLOHMANN_JSON_TARGET_NAME}
    INTERFACE
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

##
## TESTS
## create and configure the unit test target
##
include(CTest) #adds option BUILD_TESTING (default ON)

if(BUILD_TESTING AND JSON_BuildTests)
    enable_testing()
    add_subdirectory(test)
endif()

##
## INSTALL
## install header files, generate and install cmake config files for find_package()
##
include(CMakePackageConfigHelpers)
write_basic_package_version_file(
    ${NLOHMANN_JSON_CMAKE_VERSION_CONFIG_FILE} COMPATIBILITY SameMajorVersion
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
endif()
