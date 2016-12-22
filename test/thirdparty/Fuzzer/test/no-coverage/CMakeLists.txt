# These tests are not instrumented with coverage,
# but have coverage rt in the binary.

set(CMAKE_CXX_FLAGS
  "${LIBFUZZER_FLAGS_BASE} -fno-sanitize-coverage=edge,trace-cmp,indirect-calls,8bit-counters,trace-pc-guard")

set(NoCoverageTests
  UninstrumentedTest
  )

foreach(Test ${NoCoverageTests})
  add_libfuzzer_test(${Test}-NoCoverage SOURCES ../${Test}.cpp)
endforeach()


###############################################################################
# AFL Driver test
###############################################################################

add_executable(AFLDriverTest
  ../AFLDriverTest.cpp ../../afl/afl_driver.cpp)

set_target_properties(AFLDriverTest
    PROPERTIES RUNTIME_OUTPUT_DIRECTORY
    "${CMAKE_BINARY_DIR}/lib/Fuzzer/test"
    )

# Propagate value into parent directory
set(TestBinaries ${TestBinaries} AFLDriverTest PARENT_SCOPE)
