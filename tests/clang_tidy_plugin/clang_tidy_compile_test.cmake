file(COPY "${TEMPLATE_FILE}" DESTINATION "${TEST_WORK_DIR}" NO_SOURCE_PERMISSIONS)
get_filename_component(TEMPLATE_NAME "${TEMPLATE_FILE}" NAME)
set(TEST_FILE "${TEST_WORK_DIR}/${TEMPLATE_NAME}")
set(OBJECT_FILE "${TEST_WORK_DIR}/${TEMPLATE_NAME}.o")
set(CXX_STANDARD_FLAG "-std=c++17")

function(compile_test PARAMS)
    execute_process(
        COMMAND ${CXX_COMPILER} ${CXX_STANDARD_FLAG} "-I${INCLUDE_PATH}" -DUSE_REAL_HEADER ${PARAMS} -c "${TEST_FILE}" -o "${OBJECT_FILE}"
        RESULT_VARIABLE COMPILE_RESULT
        OUTPUT_VARIABLE COMPILE_OUTPUT
        ERROR_VARIABLE COMPILE_ERROR
    )

    if(NOT COMPILE_RESULT EQUAL 0)
        message(FATAL_ERROR "Compilation failed:\n${COMPILE_OUTPUT}\n${COMPILE_ERROR}")
    endif()
endfunction()

# Compile with implicit conversions enabled to prove that source compiles first
message(STATUS "Compiling ${TEST_FILE} with implicit conversions enabled")
compile_test(-DJSON_USE_IMPLICIT_CONVERSIONS=1)

# Run clang-tidy
message(STATUS "Running clang-tidy to fix implicit conversions in ${TEST_FILE}")
execute_process(
    COMMAND ${CLANG_TIDY_TOOL} -load "${PLUGIN_PATH}" "-checks=-*,modernize-nlohmann-json-explicit-conversions" "-config={}" --fix "${TEST_FILE}" -- ${CXX_STANDARD_FLAG}
    RESULT_VARIABLE CLANG_TIDY_RESULT
    OUTPUT_VARIABLE CLANG_TIDY_OUTPUT
    ERROR_VARIABLE CLANG_TIDY_ERROR
)

if(NOT CLANG_TIDY_RESULT EQUAL 0)
    message(FATAL_ERROR "clang-tidy output:\n${CLANG_TIDY_OUTPUT}\n${CLANG_TIDY_ERROR}")
endif()

# Compile with implicit conversions disabled
message(STATUS "Compiling fixed ${TEST_FILE} with implicit conversions disabled")
compile_test(-DJSON_USE_IMPLICIT_CONVERSIONS=0)

message(STATUS "clang-tidy implicit conversions fix passed")
