# Distributed under the OSI-approved BSD 3-Clause License.  See accompanying
# file Copyright.txt or https://cmake.org/licensing for details.

set(prefix "${TEST_PREFIX}")
set(suffix "${TEST_SUFFIX}")
set(spec ${TEST_SPEC})
set(extra_args ${TEST_EXTRA_ARGS})
set(properties ${TEST_PROPERTIES})
set(reporter ${TEST_REPORTER})
set(output_dir ${TEST_OUTPUT_DIR})
set(output_prefix ${TEST_OUTPUT_PREFIX})
set(output_suffix ${TEST_OUTPUT_SUFFIX})
set(script)
set(suite)
set(tests)

function(add_command NAME)
  set(_args "")
  foreach(_arg ${ARGN})
    if(_arg MATCHES "[^-./:a-zA-Z0-9_]")
      set(_args "${_args} [==[${_arg}]==]") # form a bracket_argument
    else()
      set(_args "${_args} ${_arg}")
    endif()
  endforeach()
  set(script "${script}${NAME}(${_args})\n" PARENT_SCOPE)
endfunction()

# Run test executable to get list of available tests
if(NOT EXISTS "${TEST_EXECUTABLE}")
  message(FATAL_ERROR
    "Specified test executable '${TEST_EXECUTABLE}' does not exist"
  )
endif()
execute_process(
  COMMAND ${TEST_EXECUTOR} "${TEST_EXECUTABLE}" ${spec} --list-tests --verbosity quiet
  OUTPUT_VARIABLE output
  RESULT_VARIABLE result
  WORKING_DIRECTORY "${TEST_WORKING_DIR}"
)
if(NOT ${result} EQUAL 0)
  message(FATAL_ERROR
    "Error running test executable '${TEST_EXECUTABLE}':\n"
    "  Result: ${result}\n"
    "  Output: ${output}\n"
  )
endif()

string(REPLACE "\n" ";" output "${output}")

# Run test executable to get list of available reporters
execute_process(
  COMMAND ${TEST_EXECUTOR} "${TEST_EXECUTABLE}" ${spec} --list-reporters
  OUTPUT_VARIABLE reporters_output
  RESULT_VARIABLE reporters_result
  WORKING_DIRECTORY "${TEST_WORKING_DIR}"
)
if(${reporters_result} EQUAL 0)
  message(WARNING
    "Test executable '${TEST_EXECUTABLE}' contains no reporters!\n"
  )
elseif(${reporters_result} LESS 0)
  message(FATAL_ERROR
    "Error running test executable '${TEST_EXECUTABLE}':\n"
    "  Result: ${reporters_result}\n"
    "  Output: ${reporters_output}\n"
  )
endif()
string(FIND "${reporters_output}" "${reporter}" reporter_is_valid)
if(reporter AND ${reporter_is_valid} EQUAL -1)
  message(FATAL_ERROR
    "\"${reporter}\" is not a valid reporter!\n"
  )
endif()

# Prepare reporter
if(reporter)
  set(reporter_arg "--reporter ${reporter}")
endif()

# Prepare output dir
if(output_dir AND NOT IS_ABSOLUTE ${output_dir})
  set(output_dir "${TEST_WORKING_DIR}/${output_dir}")
  if(NOT EXISTS ${output_dir})
    file(MAKE_DIRECTORY ${output_dir})
  endif()
endif()

# Parse output
foreach(line ${output})
  set(test ${line})
  # Escape characters in test case names that would be parsed by Catch2
  set(test_name ${test})
  foreach(char , [ ])
    string(REPLACE ${char} "\\${char}" test_name ${test_name})
  endforeach(char)
  # ...add output dir
  if(output_dir)
    string(REGEX REPLACE "[^A-Za-z0-9_]" "_" test_name_clean ${test_name})
    set(output_dir_arg "--out ${output_dir}/${output_prefix}${test_name_clean}${output_suffix}")
  endif()
  
  # ...and add to script
  add_command(add_test
    "${prefix}${test}${suffix}"
    ${TEST_EXECUTOR}
    "${TEST_EXECUTABLE}"
    "${test_name}"
    ${extra_args}
    "${reporter_arg}"
    "${output_dir_arg}"
  )
  add_command(set_tests_properties
    "${prefix}${test}${suffix}"
    PROPERTIES
    WORKING_DIRECTORY "${TEST_WORKING_DIR}"
    ${properties}
  )
  list(APPEND tests "${prefix}${test}${suffix}")
endforeach()

# Create a list of all discovered tests, which users may use to e.g. set
# properties on the tests
add_command(set ${TEST_LIST} ${tests})

# Write CTest script
file(WRITE "${CTEST_FILE}" "${script}")
