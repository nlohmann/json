# internal function used to implement json_feature(KEY_VALUE)
function(_json_feature_key_value key value_var)
    cmake_parse_arguments(args "NEGATE;RAW" "" "SWITCH;VALUES" ${ARGN})

    if(NOT "${args_SWITCH}" STREQUAL "")
        if(${args_SWITCH})
            # noop
        else()
            return()
        endif()
    endif()

    if(${args_RAW})
        set(value "${value_var}")
    else()
        set(value NO)
        if(args_VALUES)
            foreach(val ${args_VALUES})
                if(${value_var} STREQUAL val)
                    set(value ${val})
                    break()
                endif()
            endforeach()
        elseif(${args_NEGATE} AND NOT ${value_var} OR ${value_var})
            set(value YES)
        endif()
    endif()
    list(APPEND _JSON_FEATURE_SUMMARY KV "${key}" "${value}")
    set(_JSON_FEATURE_SUMMARY "${_JSON_FEATURE_SUMMARY}" PARENT_SCOPE)
endfunction()

#############################################################################
# json_feature(
#     KEY_VALUE <key> <value_var>
#     [VALUES <value>...]
#     [RAW] [NEGATE]
#     [SWITCH <conditional_args>...])
#
# Append feature info using <key> as description text and the boolean value
# of <value_var> converted to YES/NO.
#
# If RAW is specified, <value_var> is appended as is.
#
# If additional values are given and <value_var> matches any of them,
# <value_var> is not converted to YES/NO.
#
# If NEGATE is specified, the boolean value of <value_var> is negated.
#
# If a conditional expression consisting of <conditional_args> is listed
# following SWITCH, the feature is only added if the expression evaluates to
# TRUE.
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

macro(json_feature mode)
    if("${mode}" STREQUAL KEY_VALUE)
        _json_feature_key_value(${ARGN})
    elseif("${mode}" STREQUAL RAW)
        list(LENGTH ARGN len)
        if(${len} EQUAL 1)
            list(APPEND _JSON_FEATURE_SUMMARY R ${ARGN} _)
        else()
            message(FATAL_ERROR "json_feature(RAW) called with incorrect arguments")
        endif()
    elseif("${mode}" STREQUAL NEWLINE)
        list(APPEND _JSON_FEATURE_SUMMARY N _ _)
    else()
        message(FATAL_ERROR "json_feature() called with incorrect arguments")
    endif()
endmacro()

#############################################################################
# json_print_feature_summary()
#
# Build and print the feature summary.
#############################################################################

function(json_print_feature_summary)
    if(NOT DEFINED _JSON_FEATURE_SUMMARY)
        return()
    endif()
    if("${_JSON_FEATURE_SUMMARY}" STREQUAL "")
        return()
    endif()

    # calculate maximum key length
    set(max_key_len 0)
    set(feature_summary "${_JSON_FEATURE_SUMMARY}")
    while(NOT "${feature_summary}" STREQUAL "")
        list(GET feature_summary 0 mode)
        list(GET feature_summary 1 key)
        list(REMOVE_AT feature_summary 0 1 2)

        if("${mode}" STREQUAL KV)
            string(LENGTH "${key}" len)
            if(${len} GREATER ${max_key_len})
                set(max_key_len ${len})
            endif()
        endif()
    endwhile()

    # build feature summary string
    set(last_newline FALSE)
    set(text "[nohmann_json]: Feature summary:")
    while(NOT "${_JSON_FEATURE_SUMMARY}" STREQUAL "")
        list(GET _JSON_FEATURE_SUMMARY 0 mode)
        list(GET _JSON_FEATURE_SUMMARY 1 key)
        list(GET _JSON_FEATURE_SUMMARY 2 value)
        list(REMOVE_AT _JSON_FEATURE_SUMMARY 0 1 2)

        if("${mode}" STREQUAL KV)
            # pad key to max_key_len with spaces
            string(LENGTH "${key}" len)
            math(EXPR pad_len "${max_key_len} - ${len}")
            set(pad "")
            if(${pad_len} GREATER 1)
                foreach(i RANGE 1 ${pad_len})
                    set(pad "${pad} ")
                endforeach()
            endif()

            set(text "${text}\n   ${key}${pad} ${value}")
            set(last_newline FALSE)
        elseif("${mode}" STREQUAL R)
            set(text "${text}\n   ${key}")
            set(last_newline FALSE)
        elseif("${mode}" STREQUAL N AND NOT ${last_newline})
            if("${_JSON_FEATURE_SUMMARY}" STREQUAL "")
                # skip trailing newline
                break()
            endif()
            set(text "${text}\n")
            set(last_newline TRUE)
        endif()
    endwhile()

    message(STATUS "${text}")
endfunction()

#############################################################################
# print feature summary
#############################################################################

json_feature(KEY_VALUE "Build tests?" JSON_BuildTests)

if(JSON_BuildTests)
    json_feature(KEY_VALUE "Build the 32bit unit test?" JSON_32bitTest VALUES AUTO ONLY)
    json_feature(KEY_VALUE "Skip expensive/slow tests?" JSON_FastTests)

    if(JSON_TestDataDirectory)
        json_feature(KEY_VALUE "Test data directory:" "${JSON_TestDataDirectory}" RAW)
    else()
        json_feature(KEY_VALUE "Test data source:" "${JSON_TEST_DATA_URL} (v${JSON_TEST_DATA_VERSION})" RAW)
    endif()

    json_feature(KEY_VALUE "Execute test suite with Valgrind?" JSON_Valgrind)
    if(JSON_Valgrind)
        string (REPLACE ";" " " memcheck_command "${CMAKE_MEMORYCHECK_COMMAND};${CMAKE_MEMORYCHECK_COMMAND_OPTIONS}")
        json_feature(KEY_VALUE "Valgrind command:" "${memcheck_command}" RAW)
    endif()

    list(JOIN JSON_TEST_CXX_STANDARDS_FEATURE_INFO " " test_cxx_standards)
    if(JSON_TEST_CXX_STANDARDS_FORCED)
        set(test_cxx_standards "${test_cxx_standards} (forced)")
    endif()
    json_feature(KEY_VALUE "Test C++ standards:" "${test_cxx_standards}" RAW)
endif()

json_feature(NEWLINE)

json_feature(KEY_VALUE "Diagnostics enabled?" JSON_Diagnostics SWITCH JSON_Diagnostics)
json_feature(KEY_VALUE "Default integer enum serialization enabled?" JSON_DisableEnumSerialization NEGATE)
json_feature(KEY_VALUE "Define user-defined string literals globally?" JSON_GlobalUDLs)
json_feature(KEY_VALUE "Implicit conversions enabled?" JSON_ImplicitConversions)
json_feature(KEY_VALUE "Legacy discarded value comparison enabled?" JSON_LegacyDiscardedValueComparison)

json_feature(NEWLINE)

json_feature(KEY_VALUE "Use the multi-header code?" JSON_MultipleHeaders)
json_feature(KEY_VALUE "Include directory:" "${NLOHMANN_JSON_INCLUDE_BUILD_DIR}" RAW)
json_feature(KEY_VALUE "Include as system headers?" JSON_SystemInclude)

json_print_feature_summary()
