cmake_minimum_required(VERSION 3.5)

# detect if Catch is being bundled,
# disable testsuite in that case
if(NOT DEFINED PROJECT_NAME)
  set(NOT_SUBPROJECT ON)
endif()

option(CATCH_INSTALL_DOCS "Install documentation alongside library" ON)
option(CATCH_INSTALL_EXTRAS "Install extras alongside library" ON)
option(CATCH_DEVELOPMENT_BUILD "Build tests, enable warnings, enable Werror, etc" OFF)

include(CMakeDependentOption)
cmake_dependent_option(CATCH_BUILD_TESTING "Build the SelfTest project" ON "CATCH_DEVELOPMENT_BUILD" OFF)
cmake_dependent_option(CATCH_BUILD_EXAMPLES "Build code examples" OFF "CATCH_DEVELOPMENT_BUILD" OFF)
cmake_dependent_option(CATCH_BUILD_EXTRA_TESTS "Build extra tests" OFF "CATCH_DEVELOPMENT_BUILD" OFF)
cmake_dependent_option(CATCH_BUILD_FUZZERS "Build fuzzers" OFF "CATCH_DEVELOPMENT_BUILD" OFF)
cmake_dependent_option(CATCH_ENABLE_COVERAGE "Generate coverage for codecov.io" OFF "CATCH_DEVELOPMENT_BUILD" OFF)
cmake_dependent_option(CATCH_ENABLE_WERROR "Enables Werror during build" ON "CATCH_DEVELOPMENT_BUILD" OFF)

# Catch2's build breaks if done in-tree. You probably should not build
# things in tree anyway, but we can allow projects that include Catch2
# as a subproject to build in-tree as long as it is not in our tree.
if (CMAKE_BINARY_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
    message(FATAL_ERROR "Building in-source is not supported! Create a build dir and remove ${CMAKE_SOURCE_DIR}/CMakeCache.txt")
endif()


project(Catch2 LANGUAGES CXX VERSION 3.0.0)

# Provide path for scripts
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/CMake")
include(GNUInstallDirs)
include(CMakePackageConfigHelpers)
include(CTest)

# This variable is used in some subdirectories, so we need it here, rather
# than later in the install block
set(CATCH_CMAKE_CONFIG_DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/Catch2")

# We have some Windows builds that test `wmain` entry point,
# and we need this change to be present in all binaries that
# are built during these tests, so this is required here, before
# the subdirectories are added.
if(CATCH_TEST_USE_WMAIN)
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} /ENTRY:wmainCRTStartup")
endif()


# Basic paths
set(CATCH_DIR ${CMAKE_CURRENT_SOURCE_DIR})
set(SOURCES_DIR ${CATCH_DIR}/src/catch2)
set(SELF_TEST_DIR ${CATCH_DIR}/tests/SelfTest)
set(BENCHMARK_DIR ${CATCH_DIR}/tests/Benchmark)
set(EXAMPLES_DIR ${CATCH_DIR}/examples)

# We need to bring-in the variables defined there to this scope
add_subdirectory(src)

# Build tests only if requested
if (BUILD_TESTING AND CATCH_BUILD_TESTING AND NOT_SUBPROJECT)
    find_package(PythonInterp 3 REQUIRED)
    if (NOT PYTHONINTERP_FOUND)
        message(FATAL_ERROR "Python not found, but required for tests")
    endif()
    add_subdirectory(tests)
endif()

if(CATCH_BUILD_EXAMPLES)
    add_subdirectory(examples)
endif()

if(CATCH_BUILD_EXTRA_TESTS)
    add_subdirectory(tests/ExtraTests)
endif()

if(CATCH_BUILD_FUZZERS)
    add_subdirectory(fuzzing)
endif()

if (CATCH_DEVELOPMENT_BUILD)
    add_warnings_to_targets("${CATCH_WARNING_TARGETS}")
endif()


#option(CATCH_USE_VALGRIND "Perform SelfTests with Valgrind" OFF)
#option(CATCH_ENABLE_WERROR "Enable all warnings as errors" ON)
#
#set_property(GLOBAL PROPERTY USE_FOLDERS ON)
#
#
#
#
#
# Only perform the installation steps when Catch is not being used as
# a subproject via `add_subdirectory`, or the destinations will break,
# see https://github.com/catchorg/Catch2/issues/1373
if (NOT_SUBPROJECT)
    configure_package_config_file(
        ${CMAKE_CURRENT_LIST_DIR}/CMake/Catch2Config.cmake.in
        ${CMAKE_CURRENT_BINARY_DIR}/Catch2Config.cmake
        INSTALL_DESTINATION
          ${CATCH_CMAKE_CONFIG_DESTINATION}
    )

    ## TODO: Catch2 main target?
    ## Install some cpp file as well?

    # By default, FooConfigVersion is tied to architecture that it was
    # generated on. Because Catch2 is header-only, it is arch-independent
    # and thus Catch2ConfigVersion should not be tied to the architecture
    # it was generated on.
    #
    # CMake does not provide a direct customization point for this in
    # `write_basic_package_version_file`, but it can be accomplished
    # indirectly by temporarily redefining `CMAKE_SIZEOF_VOID_P` to an
    # empty string. Note that just undefining the variable could be
    # insufficient in cases where the variable was already in CMake cache
    set(CATCH2_CMAKE_SIZEOF_VOID_P ${CMAKE_SIZEOF_VOID_P})
    set(CMAKE_SIZEOF_VOID_P "")
    write_basic_package_version_file(
      "${CMAKE_CURRENT_BINARY_DIR}/Catch2ConfigVersion.cmake"
      COMPATIBILITY
        SameMajorVersion
    )
    set(CMAKE_SIZEOF_VOID_P ${CATCH2_CMAKE_SIZEOF_VOID_P})

    install(
      FILES
        "${CMAKE_CURRENT_BINARY_DIR}/Catch2Config.cmake"
        "${CMAKE_CURRENT_BINARY_DIR}/Catch2ConfigVersion.cmake"
      DESTINATION
        ${CATCH_CMAKE_CONFIG_DESTINATION}
    )

    # Install documentation
    if(CATCH_INSTALL_DOCS)
      install(
        DIRECTORY
          docs/
        DESTINATION
          "${CMAKE_INSTALL_DOCDIR}"
      )
    endif()

    if(CATCH_INSTALL_EXTRAS)
        # Install CMake scripts
        install(
          FILES
            "extras/ParseAndAddCatchTests.cmake"
            "extras/Catch.cmake"
            "extras/CatchAddTests.cmake"
          DESTINATION
            ${CATCH_CMAKE_CONFIG_DESTINATION}
        )
    
        # Install debugger helpers
        install(
          FILES
            "extras/gdbinit"
            "extras/lldbinit"
          DESTINATION
            ${CMAKE_INSTALL_DATAROOTDIR}/Catch2
        )
    endif()

    ## Provide some pkg-config integration
    set(PKGCONFIG_INSTALL_DIR
        "${CMAKE_INSTALL_DATAROOTDIR}/pkgconfig"
        CACHE PATH "Path where catch2.pc is installed"
    )
    configure_file(
      ${CMAKE_CURRENT_SOURCE_DIR}/CMake/catch2.pc.in
      ${CMAKE_CURRENT_BINARY_DIR}/catch2.pc
      @ONLY
    )
    configure_file(
      ${CMAKE_CURRENT_SOURCE_DIR}/CMake/catch2-with-main.pc.in
      ${CMAKE_CURRENT_BINARY_DIR}/catch2-with-main.pc
      @ONLY
    )
    install(
      FILES
        "${CMAKE_CURRENT_BINARY_DIR}/catch2.pc"
        "${CMAKE_CURRENT_BINARY_DIR}/catch2-with-main.pc"
      DESTINATION
        ${PKGCONFIG_INSTALL_DIR}
    )

    # CPack/CMake started taking the package version from project version 3.12
    # So we need to set the version manually for older CMake versions
    if(${CMAKE_VERSION} VERSION_LESS "3.12.0")
        set(CPACK_PACKAGE_VERSION ${PROJECT_VERSION})
    endif()

    set(CPACK_PACKAGE_CONTACT "https://github.com/catchorg/Catch2/")


    include( CPack )

endif(NOT_SUBPROJECT)
