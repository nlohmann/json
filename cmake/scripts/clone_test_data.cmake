# clone test data

get_filename_component(test_data_dir json_test_data ABSOLUTE)

if(NOT EXISTS ${test_data_dir})
    execute_process(COMMAND ${GIT_EXECUTABLE} clone
                                -q -c advice.detachedHead=false -b v${JSON_TEST_DATA_VERSION} --depth 1
				                -- ${JSON_TEST_DATA_URL} ${test_data_dir}
                    RESULT_VARIABLE git_result
                    OUTPUT_VARIABLE git_output
                    ERROR_VARIABLE git_output)

    if(NOT git_result EQUAL 0)
        message(FATAL_ERROR "git failed:\n${git_output}")
    endif()
endif()
