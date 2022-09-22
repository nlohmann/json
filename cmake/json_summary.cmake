#############################################################################
# json_feature_summary_begin()
#
# Initialize the feature summary buffer.
#############################################################################

function(json_feature_summary_begin)
    set(_JSON_FEATURE_SUMMARY_TEXT "" PARENT_SCOPE)
endfunction()

#############################################################################
# json_feature_summary_end()
#
# Print the feature summary buffer.
#############################################################################

function(json_feature_summary_end)
    if(NOT "${_JSON_FEATURE_SUMMARY_TEXT}" STREQUAL "")
        message(STATUS "${_JSON_FEATURE_SUMMARY_TEXT}")
    endif()

    unset(_JSON_FEATURE_SUMMARY_TEXT PARENT_SCOPE)
endfunction()

#############################################################################
# json_feature(
#     <var> <text>
#     [VALUES <value>...]
#     [NEGATE])
#
# Append feature info using <text> and the boolean value of <var> converted
# to YES/NO.
#
# If additional values are given and <var> matches any of them, <var> is not
# converted to YES/NO.
#
# If NEGATE is specified, the boolean value of <var> is negated.
#
# ---
#
# json_feature(NEWLINE)
#
# Append a new line.
#
# ---
#
# json_feature(RAW <text>)
#
# Append raw text <text> to feature summary.
#############################################################################

function(json_feature)
    if(NOT DEFINED _JSON_FEATURE_SUMMARY_TEXT)
        message(FATAL_ERROR "json_feature() called before json_feature_summary_begin()")
    endif()

    set(var "")
    set(text "")
    if(${ARGC} EQUAL 1 OR ${ARGC} GREATER 1)
        list(GET ARGN 0 var)
    endif()
    if(${ARGC} EQUAL 2 OR ${ARGC} GREATER 2)
        list(GET ARGN 1 text)
    endif()

    # json_feature(RAW <text>)
    if("${var}" STREQUAL RAW AND NOT "${text}" STREQUAL "")
        set(text "   ${text}")
    # json_feature(NEWLINE)
    elseif("${var}" STREQUAL NEWLINE AND "${text}" STREQUAL "")
        # noop
    # json_feature(<var> <text> ...)
    elseif(NOT "${var}" STREQUAL "" AND NOT "${text}" STREQUAL "")
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
        set(text "   ${text} ${state}")
    else()
        message(FATAL_ERROR "json_feature() called with incorrect arguments")
    endif()

    # add preamble if buffer is empty
    if("${_JSON_FEATURE_SUMMARY_TEXT}" STREQUAL "")
        set(_JSON_FEATURE_SUMMARY_TEXT "[nohmann_json]: Feature summary:\n")
    else()
        set(_JSON_FEATURE_SUMMARY_TEXT "${_JSON_FEATURE_SUMMARY_TEXT}\n")
    endif()

    # append to buffer
    set(_JSON_FEATURE_SUMMARY_TEXT "${_JSON_FEATURE_SUMMARY_TEXT}${text}" PARENT_SCOPE)
endfunction()

#############################################################################
# print feature summary
#############################################################################

json_feature_summary_begin()

json_feature(JSON_BuildTests "Build tests?")
if(JSON_BuildTests)
    json_feature(JSON_32bitTest "Build the 32bit unit test?" VALUES AUTO ONLY)
    json_feature(JSON_FastTests "Skip expensive/slow tests?")

    if(JSON_TestDataDirectory)
        json_feature(RAW "Test data directory: ${JSON_TestDataDirectory}")
    else()
        json_feature(RAW "Test data source: ${JSON_TEST_DATA_URL} (v${JSON_TEST_DATA_VERSION})")
    endif()

    json_feature(JSON_Valgrind "Execute test suite with Valgrind?")
    if(JSON_Valgrind)
        string (REPLACE ";" " " memcheck_command "${CMAKE_MEMORYCHECK_COMMAND};${CMAKE_MEMORYCHECK_COMMAND_OPTIONS}")
        json_feature(RAW "Valgrind command: ${memcheck_command}")
    endif()

    list(JOIN JSON_TEST_CXX_STANDARDS_FEATURE_INFO " " test_cxx_standards)
    if(JSON_TEST_CXX_STANDARDS_FORCED)
        set(test_cxx_standards "${test_cxx_standards} (forced)")
    endif()
    json_feature(RAW "Test C++ standards: ${test_cxx_standards}")
endif()

json_feature(NEWLINE)

json_feature(JSON_Diagnostics "Diagnostics enabled?")
json_feature(JSON_DisableEnumSerialization "Default integer enum serialization enabled?" NEGATE)
json_feature(JSON_GlobalUDLs "Define user-defined string literals globally?")
json_feature(JSON_ImplicitConversions "Implicit conversions enabled?")
json_feature(JSON_LegacyDiscardedValueComparison "Legacy discarded value comparison enabled?")

json_feature(NEWLINE)

json_feature(JSON_MultipleHeaders "Use the multi-header code?")
json_feature(RAW "Include directory: ${NLOHMANN_JSON_INCLUDE_BUILD_DIR}")
json_feature(JSON_SystemInclude "Include as system headers?")

json_feature_summary_end()
