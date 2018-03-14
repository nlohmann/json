cmake_minimum_required(VERSION 3.0.0)

##
## PROJECT
## name and version
##
project(nlohmann_json VERSION 3.1.2 LANGUAGES CXX)

##
## INCLUDE
##
##
include(ExternalProject)

##
## OPTIONS
##
option(JSON_BuildTests "Build the unit tests when BUILD_TESTING is enabled." ON)
option(JSON_MultipleHeaders "Use non-amalgamated version of the library." OFF)

##
## CONFIGURATION
##
set(NLOHMANN_JSON_TARGET_NAME               ${PROJECT_NAME})
set(NLOHMANN_JSON_CONFIG_INSTALL_DIR        "lib/cmake/${PROJECT_NAME}")
set(NLOHMANN_JSON_INCLUDE_INSTALL_DIR       "include")
set(NLOHMANN_JSON_TARGETS_EXPORT_NAME       "${PROJECT_NAME}Targets")
set(NLOHMANN_JSON_CMAKE_CONFIG_TEMPLATE     "cmake/config.cmake.in")
set(NLOHMANN_JSON_CMAKE_CONFIG_DIR          "${CMAKE_CURRENT_BINARY_DIR}/cmake_config")
set(NLOHMANN_JSON_CMAKE_VERSION_CONFIG_FILE "${NLOHMANN_JSON_CMAKE_CONFIG_DIR}/${PROJECT_NAME}ConfigVersion.cmake")
set(NLOHMANN_JSON_CMAKE_PROJECT_CONFIG_FILE "${NLOHMANN_JSON_CMAKE_CONFIG_DIR}/${PROJECT_NAME}Config.cmake")

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

target_include_directories(
    ${NLOHMANN_JSON_TARGET_NAME}
    INTERFACE
    $<BUILD_INTERFACE:${NLOHMANN_JSON_INCLUDE_BUILD_DIR}>
    $<INSTALL_INTERFACE:include>
)

## add debug view defintion file for msvc (natvis) [cmake <= 3.2.2 does not support export of source files]
if (MSVC AND CMAKE_VERSION VERSION_GREATER "3.2.2")
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
configure_package_config_file(
    ${NLOHMANN_JSON_CMAKE_CONFIG_TEMPLATE}
    ${NLOHMANN_JSON_CMAKE_PROJECT_CONFIG_FILE}
    INSTALL_DESTINATION ${NLOHMANN_JSON_CONFIG_INSTALL_DIR}
)

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
install(
    TARGETS ${NLOHMANN_JSON_TARGET_NAME}
    EXPORT ${NLOHMANN_JSON_TARGETS_EXPORT_NAME}
    INCLUDES DESTINATION ${NLOHMANN_JSON_INCLUDE_INSTALL_DIR}
)
install(
    EXPORT ${NLOHMANN_JSON_TARGETS_EXPORT_NAME}
    DESTINATION ${NLOHMANN_JSON_CONFIG_INSTALL_DIR}
)
