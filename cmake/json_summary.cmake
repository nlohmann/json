# ANSI codes
set(rst "")
set(bld "")
# no color output on Windows or if disabled via CLICOLOR=0/CLICOLOR_FORCE=0
if(NOT WIN32 AND NOT ("$ENV{CLICOLOR}" STREQUAL "0" OR "$ENV{CLICOLOR_FORCE}" STREQUAL "0"))
    string(ASCII 27 esc)
    set(rst "${esc}[0m") # reset
    set(bld "${esc}[1m") # bold
endif()

#############################################################################
# json_feature(
#     var text
#     [VALUES <value>...]
#     [NEGATE])
#
# Print feature info using <text> and the boolean value of <var> converted to
# YES/NO.
#
# If additional values are given and <var> matches any of them, <var> is not
# converted to YES/NO.
#
# If NEGATE is specified, the boolean value of <var> is negated.
#############################################################################

function(json_feature var text)
    cmake_parse_arguments(args "NEGATE" "" "VALUES" ${ARGN})

    set(state NO)
    if(args_VALUES)
        foreach(value ${args_VALUES})
            if(${var} STREQUAL value)
                set(state ${value})
                break()
            endif()
        endforeach()
    elseif(${args_NEGATE} AND NOT ${var} OR ${var})
        set(state YES)
    endif()

    message("   ${text} ${bld}${state}${rst}")
endfunction()

#############################################################################
# print feature summary
#############################################################################

message(STATUS "[nohmann_json]: Feature summary:")

json_feature(JSON_BuildTests "Build tests?")
if(JSON_BuildTests)
    json_feature(JSON_32bitTest "Build the 32bit unit test?" VALUES AUTO ONLY)
    json_feature(JSON_FastTests "Skip expensive/slow tests?")

    if(JSON_TEST_DATA_DIRECTORY)
        message("   Test data: ${JSON_TEST_DATA_DIRECTORY}")
    else()
        message("   Test data: ${JSON_TEST_DATA_URL} (v${JSON_TEST_DATA_VERSION})")
    endif()

    json_feature(JSON_Valgrind "Execute test suite with Valgrind?")
    if(JSON_Valgrind)
        message("   Valgrind command: ${CMAKE_MEMORYCHECK_COMMAND}" ${CMAKE_MEMORYCHECK_COMMAND_OPTIONS})
    endif()

    set(test_cxx_standards "")
    foreach(cxx_standard ${JSON_TEST_CXX_STANDARDS_FEATURE_INFO})
        if(NOT cxx_standard MATCHES "^[\[].+[\]]$")
            set(cxx_standard "${bld}${cxx_standard}${rst}")
        endif()
        set(test_cxx_standards "${test_cxx_standards} ${cxx_standard}")
    endforeach()

    if(JSON_TEST_CXX_STANDARDS_FORCED)
        set(test_cxx_standards "${test_cxx_standards} ${bld}(forced)${rst}")
    endif()
    message("   Test C++ standards:${test_cxx_standards}")
endif()

message("")

json_feature(JSON_Diagnostics "Diagnostics enabled?" NEGATE)
json_feature(JSON_DisableEnumSerialization "Default integer enum serialization enabled?")
json_feature(JSON_GlobalUDLs "Define user-defined string literals globally?")
json_feature(JSON_ImplicitConversions "Implicit conversions enabled?")
json_feature(JSON_LegacyDiscardedValueComparison "Legacy discarded value comparison enabled?")

message("")

json_feature(JSON_MultipleHeaders "Use the multi-header code?")
message("   Include directory: ${NLOHMANN_JSON_INCLUDE_BUILD_DIR}")
json_feature(JSON_SystemInclude "Include as system headers?")
