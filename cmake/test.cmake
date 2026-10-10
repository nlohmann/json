set(_json_test_cmake_list_file ${CMAKE_CURRENT_LIST_FILE})

#############################################################################
# download test data
#############################################################################

include(download_test_data)

# test fixture to download test data
add_test(NAME "download_test_data" COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR}
    --target download_test_data
)
set_tests_properties(download_test_data PROPERTIES FIXTURES_SETUP TEST_DATA)

if(JSON_Valgrind)
    find_program(CMAKE_MEMORYCHECK_COMMAND valgrind)
    message(STATUS "Executing test suite with Valgrind (${CMAKE_MEMORYCHECK_COMMAND})")
    set(memcheck_command "${CMAKE_MEMORYCHECK_COMMAND} ${CMAKE_MEMORYCHECK_COMMAND_OPTIONS} --error-exitcode=1 --leak-check=full")
    separate_arguments(memcheck_command)
endif()

#############################################################################
# detect standard support
#############################################################################

# C++11 is the minimum required
set(compiler_supports_cpp_11 TRUE)

foreach(feature ${CMAKE_CXX_COMPILE_FEATURES})
    if (${feature} STREQUAL cxx_std_14)
        set(compiler_supports_cpp_14 TRUE)
    elseif (${feature} STREQUAL cxx_std_17)
        set(compiler_supports_cpp_17 TRUE)
    elseif (${feature} STREQUAL cxx_std_20)
        set(compiler_supports_cpp_20 TRUE)
    elseif (${feature} STREQUAL cxx_std_23)
        set(compiler_supports_cpp_23 TRUE)
    elseif (${feature} STREQUAL cxx_std_26)
        set(compiler_supports_cpp_26 TRUE)
    endif()
endforeach()

#############################################################################
# test functions
#############################################################################

#############################################################################
# json_test_set_test_options(
#     all|<tests>
#     [CXX_STANDARDS all|<args>...]
#     [COMPILE_DEFINITIONS <args>...]
#     [COMPILE_FEATURES <args>...]
#     [COMPILE_OPTIONS <args>...]
#     [LINK_LIBRARIES <args>...]
#     [LINK_OPTIONS <args>...]
#     [TEST_PROPERTIES <args>...])
#
# Supply test- and standard-specific build settings and/or test properties.
# Specify multiple tests using a list e.g., "test-foo;test-bar".
#
# Must be called BEFORE the test is created.
#############################################################################

function(json_test_set_test_options tests)
    cmake_parse_arguments(args "" ""
        "CXX_STANDARDS;COMPILE_DEFINITIONS;COMPILE_FEATURES;COMPILE_OPTIONS;LINK_LIBRARIES;LINK_OPTIONS;TEST_PROPERTIES"
        ${ARGN})

    if(NOT args_CXX_STANDARDS)
        set(args_CXX_STANDARDS "all")
    endif()

    foreach(test ${tests})
        if("${test}" STREQUAL "all")
            set(test "")
        endif()

        foreach(cxx_standard ${args_CXX_STANDARDS})
            if("${cxx_standard}" STREQUAL "all")
                if("${test}" STREQUAL "")
                    message(FATAL_ERROR "Not supported. Change defaults in: ${_json_test_cmake_list_file}")
                endif()
                set(test_interface _json_test_interface_${test})
            else()
                set(test_interface _json_test_interface_${test}_cpp_${cxx_standard})
            endif()

            if(NOT TARGET ${test_interface})
                add_library(${test_interface} INTERFACE)
            endif()

            target_compile_definitions(${test_interface} INTERFACE ${args_COMPILE_DEFINITIONS})
            target_compile_features(${test_interface} INTERFACE ${args_COMPILE_FEATURES})
            target_compile_options(${test_interface} INTERFACE ${args_COMPILE_OPTIONS})
            target_link_libraries (${test_interface} INTERFACE ${args_LINK_LIBRARIES})
            target_link_options(${test_interface} INTERFACE ${args_LINK_OPTIONS})
            set_property(DIRECTORY PROPERTY
                ${test_interface}_TEST_PROPERTIES "${args_TEST_PROPERTIES}"
            )
        endforeach()
    endforeach()
endfunction()

# for internal use by _json_test_add_test()
function(_json_test_apply_test_properties test_target properties_target)
    get_property(test_properties DIRECTORY PROPERTY ${properties_target}_TEST_PROPERTIES)
    if(test_properties)
        set_tests_properties(${test_target} PROPERTIES ${test_properties})
    endif()
endfunction()

# for internal use by _json_test_add_test() and _json_test_add_unity_batch():
# registers the CTest test <test_name>_cpp<cxx_standard> (plus its Valgrind
# variant), which runs the executable target <test_target> with the arguments
# in ARGN, and applies the test properties of the test- and standard-specific
# interface targets
function(_json_test_register_test test_name test_target cxx_standard)
    set(ctest_name ${test_name}_cpp${cxx_standard})

    if (JSON_FastTests)
        add_test(NAME ${ctest_name}
            COMMAND ${test_target} ${DOCTEST_TEST_FILTER} ${ARGN}
            WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
        )
    else()
        add_test(NAME ${ctest_name}
            COMMAND ${test_target} ${DOCTEST_TEST_FILTER} ${ARGN} --no-skip
            WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
        )
    endif()
    set_tests_properties(${ctest_name} PROPERTIES LABELS "all" FIXTURES_REQUIRED TEST_DATA)

    # apply standard-specific test properties
    if(TARGET _json_test_interface__cpp_${cxx_standard})
        _json_test_apply_test_properties(${ctest_name} _json_test_interface__cpp_${cxx_standard})
    endif()

    # apply test-specific test properties
    if(TARGET _json_test_interface_${test_name})
        _json_test_apply_test_properties(${ctest_name} _json_test_interface_${test_name})
    endif()

    # apply test- and standard-specific test properties
    if(TARGET _json_test_interface_${test_name}_cpp_${cxx_standard})
        _json_test_apply_test_properties(${ctest_name}
            _json_test_interface_${test_name}_cpp_${cxx_standard}
        )
    endif()

    if(JSON_Valgrind)
        add_test(NAME ${ctest_name}_valgrind
            COMMAND ${memcheck_command} $<TARGET_FILE:${test_target}> ${DOCTEST_TEST_FILTER} ${ARGN}
            WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
        )
        set_tests_properties(${ctest_name}_valgrind PROPERTIES
            LABELS "valgrind" FIXTURES_REQUIRED TEST_DATA
        )
    endif()
endfunction()

# for internal use by json_test_add_test_for()
function(_json_test_add_test test_name file main cxx_standard)
    set(test_target ${test_name}_cpp${cxx_standard})

    if(TARGET ${test_target})
        message(FATAL_ERROR "Target ${test_target} has already been added.")
    endif()

    add_executable(${test_target} ${file})
    target_link_libraries(${test_target} PRIVATE ${main})

    # set and require C++ standard
    set_target_properties(${test_target} PROPERTIES
        CXX_STANDARD ${cxx_standard}
        CXX_STANDARD_REQUIRED ON
    )

    # apply standard-specific build settings
    if(TARGET _json_test_interface__cpp_${cxx_standard})
        target_link_libraries(${test_target} PRIVATE _json_test_interface__cpp_${cxx_standard})
    endif()

    # apply test-specific build settings
    if(TARGET _json_test_interface_${test_name})
        target_link_libraries(${test_target} PRIVATE _json_test_interface_${test_name})
    endif()

    # apply test- and standard-specific build settings
    if(TARGET _json_test_interface_${test_name}_cpp_${cxx_standard})
        target_link_libraries(${test_target} PRIVATE
            _json_test_interface_${test_name}_cpp_${cxx_standard}
        )
    endif()

    _json_test_register_test(${test_name} ${test_target} ${cxx_standard})
endfunction()

#############################################################################
# json_test_add_test_for(
#     <file>
#     [NAME <name>]
#     MAIN <main>
#     [CXX_STANDARDS <version_number>...] [FORCE])
#
# Given a <file> unit-foo.cpp, produces
#
#     test-foo_cpp<version_number>
#
# if C++ standard <version_number> is supported by the compiler and the
# source file contains JSON_HAS_CPP_<version_number>.
# Use NAME <name> to override the filename-derived test name.
# Use FORCE to create the test regardless of the file containing
# JSON_HAS_CPP_<version_number>.
#
# Tests that depend on the C++ standard (e.g., because they use the macros
# JSON_HAS_FILESYSTEM, JSON_HAS_RANGES, or JSON_HAS_THREE_WAY_COMPARISON)
# should not make the whole of a large unit-foo.cpp be rebuilt for every
# standard. Put them into a separate file unit-foo-cpp<NN>.cpp (see, e.g.,
# unit-items-cpp17.cpp) which wraps its content in #ifdef JSON_HAS_CPP_<NN>.
# Then, unit-foo.cpp itself contains no JSON_HAS_CPP_<NN> and is only built for
# C++11.
# Test targets are linked against <main>.
# CXX_STANDARDS defaults to "11".
#############################################################################

function(json_test_add_test_for file)
    cmake_parse_arguments(args "FORCE" "MAIN;NAME" "CXX_STANDARDS" ${ARGN})

    if("${args_MAIN}" STREQUAL "")
        message(FATAL_ERROR "Required argument MAIN <main> missing.")
    endif()

    if("${args_NAME}" STREQUAL "")
        get_filename_component(file_basename ${file} NAME_WE)
        string(REGEX REPLACE "unit-(.+)" "test-\\1" test_name ${file_basename})
    else()
        set(test_name ${args_NAME})
        if(NOT test_name MATCHES "test-.+")
            message(FATAL_ERROR "Test name must start with 'test-'.")
        endif()
    endif()

    if("${args_CXX_STANDARDS}" STREQUAL "")
        set(args_CXX_STANDARDS 11)
    endif()

    file(READ ${file} file_content)
    foreach(cxx_standard ${args_CXX_STANDARDS})
        if(NOT compiler_supports_cpp_${cxx_standard})
            continue()
        endif()

        # add unconditionally if C++11 (default) or forced
        if(NOT ("${cxx_standard}" STREQUAL 11 OR args_FORCE))
            string(FIND "${file_content}" JSON_HAS_CPP_${cxx_standard} has_cpp_found)
            if(${has_cpp_found} EQUAL -1)
                continue()
            endif()
        endif()

        _json_test_add_test(${test_name} ${file} ${args_MAIN} ${cxx_standard})
    endforeach()
endfunction()

# for internal use by json_test_add_unity_tests(): sets <result> to whether the
# (absolute) <file> is built for <cxx_standard>; same rule as in
# json_test_add_test_for(): C++11 always, others only if the file contains
# JSON_HAS_CPP_<cxx_standard> or <force> is set
function(_json_test_unity_applies file cxx_standard force result)
    set(${result} TRUE PARENT_SCOPE)
    if(NOT ("${cxx_standard}" STREQUAL 11 OR force))
        file(READ ${file} file_content)
        string(FIND "${file_content}" JSON_HAS_CPP_${cxx_standard} has_cpp_found)
        if(${has_cpp_found} EQUAL -1)
            set(${result} FALSE PARENT_SCOPE)
        endif()
    endif()
endfunction()

# for internal use by json_test_add_unity_tests(): creates the executable
# test-unity-<batch_name>_cpp<cxx_standard> from the (absolute) source files
# in ARGN, which are #include-d by a generated source file, and registers one
# CTest test per source file that runs only the test cases of that file; if
# <private> is true, the generated file defines JSON_TESTS_PRIVATE first
function(_json_test_add_unity_batch batch_name cxx_standard main private)
    set(batch_target test-unity-${batch_name}_cpp${cxx_standard})
    set(batch_source ${PROJECT_BINARY_DIR}/tests/unity/${batch_target}.cpp)

    set(batch_content "// generated by cmake/test.cmake; do not edit\n")
    if(private)
        string(APPEND batch_content "// at least one file of this batch needs access to private members of the library\n")
        string(APPEND batch_content "#define JSON_TESTS_PRIVATE\n")
        # the files define the macro again; mark this definition as used, as
        # -Wunused-macros reports an unused definition when it is redefined
        string(APPEND batch_content "#ifdef JSON_TESTS_PRIVATE\n#endif\n")
    endif()
    foreach(file ${ARGN})
        string(APPEND batch_content "#include \"${file}\" // NOLINT(bugprone-suspicious-include)\n")
    endforeach()

    # only touch the generated file if it changed to keep incremental builds incremental
    set(old_content "")
    if(EXISTS ${batch_source})
        file(READ ${batch_source} old_content)
    endif()
    if(NOT "${old_content}" STREQUAL "${batch_content}")
        file(WRITE ${batch_source} "${batch_content}")
    endif()

    add_executable(${batch_target} ${batch_source})
    target_link_libraries(${batch_target} PRIVATE ${main})
    set_target_properties(${batch_target} PROPERTIES
        CXX_STANDARD ${cxx_standard}
        CXX_STANDARD_REQUIRED ON
    )
    if(TARGET _json_test_interface__cpp_${cxx_standard})
        target_link_libraries(${batch_target} PRIVATE _json_test_interface__cpp_${cxx_standard})
    endif()

    # rebuild the batch when one of its files changes, and show the files in IDEs;
    # files that are also built standalone (VARIANT_FILES) are left out, as
    # HEADER_FILE_ONLY is a per-file property and would also affect those targets
    set_source_files_properties(${batch_source} PROPERTIES OBJECT_DEPENDS "${ARGN}")
    foreach(file ${ARGN})
        if(NOT file IN_LIST _json_test_unity_variant_files)
            set_source_files_properties(${file} PROPERTIES HEADER_FILE_ONLY ON)
            target_sources(${batch_target} PRIVATE ${file})
        endif()
    endforeach()

    foreach(file ${ARGN})
        get_filename_component(file_basename ${file} NAME_WE)
        string(REGEX REPLACE "unit-(.+)" "test-\\1" test_name ${file_basename})

        # run only the test cases defined in this file (and in the shared
        # make_test_data_available.hpp if the file uses it)
        file(READ ${file} file_content)
        set(source_filter "--source-file=*${file_basename}.cpp")
        string(FIND "${file_content}" make_test_data_available.hpp uses_test_data)
        if(NOT ${uses_test_data} EQUAL -1)
            string(APPEND source_filter ",*make_test_data_available.hpp")
        endif()

        _json_test_register_test(${test_name} ${batch_target} ${cxx_standard} "${source_filter}")
    endforeach()
endfunction()

#############################################################################
# json_test_add_unity_tests(
#     FILES <files>...
#     MAIN <main>
#     [CXX_STANDARDS <version_number>...] [FORCE]
#     [BATCH_SIZE <size>]
#     [GROUPS <group>...]
#     [VARIANT_FILES <files>...])
#
# Like calling json_test_add_test_for(<file> MAIN <main> ...) for each of the
# <files>, but compiles several files together to speed up the build: for each
# C++ standard, the files are split into batches of <size> files (default: 8)
# and each batch is built as a single executable
#
#     test-unity-<pool><index>_cpp<version_number>
#
# whose generated source file #include-s the files of the batch (so they share
# the template instantiations of the library). The tests are still named
# test-foo_cpp<version_number>, one per file, but run the batch executable with
# a doctest filter that selects the test cases of that file only.
#
# Files are only batched with files that agree on the macros defined before
# the library is included: files that define at most JSON_TESTS_PRIVATE (or
# macros derived from global compile definitions) form the pools "plain" and
# "private". All other files are added with json_test_add_test_for() as usual,
# as are files with test-specific build settings (see
# json_test_set_test_options()) and the files listed in the explicit
# exclusion list below.
# Each <group> names a list variable json_test_unity_group_<group> of test file
# stems (file names without "unit-" and ".cpp"). The batchable files of a group
# are compiled together (regardless of BATCH_SIZE) as one executable
#
#     test-unity-<group>_cpp<version_number>
#
# so that related tests, which instantiate the same templates, share one
# translation unit. A group may mix the pools "plain" and "private"; if any of
# its files needs JSON_TESTS_PRIVATE, the whole group is built with it. Files
# that cannot be batched stay standalone even if they are listed in a group.
# Files in no group are batched by BATCH_SIZE as described above.
# <files> in VARIANT_FILES are also built standalone with other settings, so
# they are not marked as header-only sources of the batch.
#############################################################################

function(json_test_add_unity_tests)
    cmake_parse_arguments(args "FORCE" "MAIN;BATCH_SIZE" "FILES;CXX_STANDARDS;VARIANT_FILES;GROUPS" ${ARGN})

    if("${args_MAIN}" STREQUAL "")
        message(FATAL_ERROR "Required argument MAIN <main> missing.")
    endif()

    if("${args_BATCH_SIZE}" STREQUAL "")
        set(args_BATCH_SIZE 8)
    endif()

    if("${args_CXX_STANDARDS}" STREQUAL "")
        set(args_CXX_STANDARDS 11)
    endif()

    if(args_FORCE)
        set(force FORCE)
    else()
        set(force "")
    endif()

    set(_json_test_unity_variant_files "")
    foreach(file ${args_VARIANT_FILES})
        get_filename_component(file ${file} ABSOLUTE)
        list(APPEND _json_test_unity_variant_files ${file})
    endforeach()

    # files that must not be merged into a batch: unit-32bit.cpp is only built
    # for 32bit targets, unit-no-macro-leak.cpp checks that including the
    # library defines no unprefixed macro, which any other file would disturb,
    # and unit-noexcept.cpp suppresses GCC's -Wnoexcept around its include of
    # the library, which has no effect once another file included it first
    set(standalone_files unit-32bit.cpp unit-no-macro-leak.cpp unit-noexcept.cpp)

    set(harmless_macros "^(DOCTEST_.*|SKIP_TESTS_FOR_.*|JSON_TEST_DEPRECATED_FUNCTIONS_DELETED|JSON_TEST_STRICT_NUL_HANDLING_ENABLED|JSON_TEST_STRINGIZE)$")

    # classify the files
    set(plain_files "")
    set(private_files "")
    set(standalone_abs_files "")
    foreach(file ${args_FILES})
        get_filename_component(file_name ${file} NAME)
        get_filename_component(file_basename ${file} NAME_WE)
        string(REGEX REPLACE "unit-(.+)" "test-\\1" test_name ${file_basename})

        set(batchable TRUE)
        if(file_name IN_LIST standalone_files)
            set(batchable FALSE)
        endif()
        if(TARGET _json_test_interface_${test_name})
            set(batchable FALSE)
        endif()
        foreach(cxx_standard ${args_CXX_STANDARDS})
            if(TARGET _json_test_interface_${test_name}_cpp_${cxx_standard})
                set(batchable FALSE)
            endif()
        endforeach()

        set(pool plain)
        if(batchable)
            # collect the macros (un)defined before the library is included
            file(READ ${file} file_content)
            string(FIND "${file_content}" "#include <nlohmann/" include_position)
            if(NOT ${include_position} EQUAL -1)
                string(SUBSTRING "${file_content}" 0 ${include_position} file_content)
            endif()
            string(REGEX MATCHALL "(^|\n)[ \t]*#[ \t]*(define|undef)[ \t]+[A-Za-z_0-9]+" directives "${file_content}")
            foreach(directive ${directives})
                string(REGEX REPLACE "^.*[ \t]([A-Za-z_0-9]+)$" "\\1" macro "${directive}")
                if(macro MATCHES "${harmless_macros}")
                    continue()
                elseif("${macro}" STREQUAL JSON_TESTS_PRIVATE)
                    set(pool private)
                else()
                    set(batchable FALSE)
                endif()
            endforeach()
        endif()

        get_filename_component(file_abs ${file} ABSOLUTE)
        if(NOT batchable)
            list(APPEND standalone_abs_files ${file_abs})
            json_test_add_test_for(${file} MAIN ${args_MAIN} CXX_STANDARDS ${args_CXX_STANDARDS} ${force})
            continue()
        endif()
        get_filename_component(file ${file} ABSOLUTE)
        list(APPEND ${pool}_files ${file})
    endforeach()

    # resolve the explicit groups: group_<name>_files are the (absolute) files
    # of the group, group_<name>_private tells whether one of them is private
    set(grouped_files "")
    foreach(group ${args_GROUPS})
        if(NOT DEFINED json_test_unity_group_${group})
            message(FATAL_ERROR "Unity test group '${group}' is not defined (json_test_unity_group_${group}).")
        endif()
        set(group_${group}_files "")
        set(group_${group}_private FALSE)
        foreach(stem ${json_test_unity_group_${group}})
            # check against the source directory, because FILES may be filtered (JSON_TestShard)
            get_filename_component(file ${CMAKE_CURRENT_SOURCE_DIR}/src/unit-${stem}.cpp ABSOLUTE)
            if(NOT EXISTS ${file})
                message(FATAL_ERROR "Unity test group '${group}' lists '${stem}', but ${file} does not exist.")
            endif()
            if(file IN_LIST grouped_files)
                message(FATAL_ERROR "Unity test file unit-${stem}.cpp is listed in more than one group (second: '${group}').")
            endif()
            list(APPEND grouped_files ${file})

            if(file IN_LIST standalone_abs_files)
                message(STATUS "Unity test group '${group}': unit-${stem}.cpp cannot be batched and stays standalone")
            elseif(file IN_LIST plain_files)
                list(APPEND group_${group}_files ${file})
                list(REMOVE_ITEM plain_files ${file})
            elseif(file IN_LIST private_files)
                list(APPEND group_${group}_files ${file})
                list(REMOVE_ITEM private_files ${file})
                set(group_${group}_private TRUE)
            endif()
        endforeach()
    endforeach()

    foreach(cxx_standard ${args_CXX_STANDARDS})
        if(NOT compiler_supports_cpp_${cxx_standard})
            continue()
        endif()

        # explicit groups: one batch per group
        foreach(group ${args_GROUPS})
            set(batch_files "")
            foreach(file ${group_${group}_files})
                _json_test_unity_applies(${file} ${cxx_standard} "${force}" applies)
                if(applies)
                    list(APPEND batch_files ${file})
                endif()
            endforeach()
            if(batch_files)
                _json_test_add_unity_batch(${group} ${cxx_standard} ${args_MAIN} ${group_${group}_private} ${batch_files})
            endif()
        endforeach()

        # remaining files: batches of BATCH_SIZE files per pool
        foreach(pool plain private)
            set(is_private FALSE)
            if(pool STREQUAL private)
                set(is_private TRUE)
            endif()

            set(batch_files "")
            set(batch_count 0)
            set(batch_index 0)
            foreach(file ${${pool}_files})
                _json_test_unity_applies(${file} ${cxx_standard} "${force}" applies)
                if(NOT applies)
                    continue()
                endif()

                list(APPEND batch_files ${file})
                math(EXPR batch_count "${batch_count} + 1")
                if(batch_count EQUAL args_BATCH_SIZE)
                    _json_test_add_unity_batch(${pool}${batch_index} ${cxx_standard} ${args_MAIN} ${is_private} ${batch_files})
                    set(batch_files "")
                    set(batch_count 0)
                    math(EXPR batch_index "${batch_index} + 1")
                endif()
            endforeach()
            if(batch_files)
                _json_test_add_unity_batch(${pool}${batch_index} ${cxx_standard} ${args_MAIN} ${is_private} ${batch_files})
            endif()
        endforeach()
    endforeach()
endfunction()

#############################################################################
# json_test_should_build_32bit_test(
#     <build_32bit_var> <build_32bit_only_var> <input>)
#
# Check if the 32bit unit test should be built based on the value of <input>
# and store the result in the variables <build_32bit_var> and
# <build_32bit_only_var>.
#############################################################################

function(json_test_should_build_32bit_test build_32bit_var build_32bit_only_var input)
    set(${build_32bit_only_var} OFF PARENT_SCOPE)
    string(TOUPPER "${input}" ${build_32bit_var})
    if("${${build_32bit_var}}" STREQUAL AUTO)
        # check if compiler is targeting 32bit by default
        include(CheckTypeSize)
        check_type_size("size_t" sizeof_size_t LANGUAGE CXX)
        if(${sizeof_size_t} AND ${sizeof_size_t} EQUAL 4)
            message(STATUS "Auto-enabling 32bit unit test.")
            set(${build_32bit_var} ON)
        else()
            set(${build_32bit_var} OFF)
        endif()
    elseif("${${build_32bit_var}}" STREQUAL ONLY)
        set(${build_32bit_only_var} ON PARENT_SCOPE)
    endif()

    set(${build_32bit_var} "${${build_32bit_var}}" PARENT_SCOPE)
endfunction()
