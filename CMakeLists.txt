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
include(GNUInstallDirs)

set(NLOHMANN_JSON_TARGET_NAME               ${PROJECT_NAME})
set(NLOHMANN_JSON_CONFIG_INSTALL_DIR        "${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME}" CACHE INTERNAL "")
set(NLOHMANN_JSON_INCLUDE_INSTALL_DIR       "${CMAKE_INSTALL_INCLUDEDIR}")
set(NLOHMANN_JSON_TARGETS_EXPORT_NAME       "${PROJECT_NAME}Targets")
set(NLOHMANN_JSON_CMAKE_MODULE_PATH         "${PROJECT_SOURCE_DIR}/cmake")
set(NLOHMANN_JSON_CMAKE_CONFIG_TEMPLATE     "${NLOHMANN_JSON_CMAKE_MODULE_PATH}/config.cmake.in")
set(NLOHMANN_JSON_CMAKE_CONFIG_DIR          "${CMAKE_CURRENT_BINARY_DIR}")
set(NLOHMANN_JSON_CMAKE_VERSION_CONFIG_FILE "${NLOHMANN_JSON_CMAKE_CONFIG_DIR}/${PROJECT_NAME}ConfigVersion.cmake")
set(NLOHMANN_JSON_CMAKE_PROJECT_CONFIG_FILE "${NLOHMANN_JSON_CMAKE_CONFIG_DIR}/${PROJECT_NAME}Config.cmake")
set(NLOHMANN_JSON_CMAKE_PROJECT_TARGETS_FILE "${NLOHMANN_JSON_CMAKE_CONFIG_DIR}/${PROJECT_NAME}Targets.cmake")

list(APPEND CMAKE_MODULE_PATH "${NLOHMANN_JSON_CMAKE_MODULE_PATH}")

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

## We need to list files explicitly before exporting them to Bazel.
set(NLOHMANN_JSON_HEADERS
    nlohmann/adl_serializer.hpp
    nlohmann/json_fwd.hpp
    nlohmann/thirdparty/hedley/hedley_undef.hpp
    nlohmann/thirdparty/hedley/hedley.hpp
    nlohmann/json.hpp
    nlohmann/detail/json_pointer.hpp
    nlohmann/detail/value_t.hpp
    nlohmann/detail/input/json_sax.hpp
    nlohmann/detail/input/lexer.hpp
    nlohmann/detail/input/input_adapters.hpp
    nlohmann/detail/input/position_t.hpp
    nlohmann/detail/input/binary_reader.hpp
    nlohmann/detail/input/parser.hpp
    nlohmann/detail/iterators/internal_iterator.hpp
    nlohmann/detail/iterators/iteration_proxy.hpp
    nlohmann/detail/iterators/json_reverse_iterator.hpp
    nlohmann/detail/iterators/iterator_traits.hpp
    nlohmann/detail/iterators/iter_impl.hpp
    nlohmann/detail/iterators/primitive_iterator.hpp
    nlohmann/detail/json_ref.hpp
    nlohmann/detail/macro_scope.hpp
    nlohmann/detail/macro_unscope.hpp
    nlohmann/detail/exceptions.hpp
    nlohmann/detail/output/output_adapters.hpp
    nlohmann/detail/output/serializer.hpp
    nlohmann/detail/output/binary_writer.hpp
    nlohmann/detail/conversions/from_json.hpp
    nlohmann/detail/conversions/to_chars.hpp
    nlohmann/detail/conversions/to_json.hpp
    nlohmann/detail/meta/void_t.hpp
    nlohmann/detail/meta/cpp_future.hpp
    nlohmann/detail/meta/detected.hpp
    nlohmann/detail/meta/is_sax.hpp
    nlohmann/detail/meta/type_traits.hpp
)
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

include(CreateBazelConfig)
create_bazel_config(${NLOHMANN_JSON_HEADERS})

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
