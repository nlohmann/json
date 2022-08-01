# Build all these tests with -O0, otherwise optimizations may merge some
# basic blocks and we'll fail to discover the targets.
# We change the flags for every build type because we might be doing
# a multi-configuration build (e.g. Xcode) where CMAKE_BUILD_TYPE doesn't
# mean anything.
set(variables_to_filter
  CMAKE_CXX_FLAGS_RELEASE
  CMAKE_CXX_FLAGS_DEBUG
  CMAKE_CXX_FLAGS_RELWITHDEBINFO
  CMAKE_CXX_FLAGS_MINSIZEREL
  LIBFUZZER_FLAGS_BASE
  )
foreach (VARNAME ${variables_to_filter})
  string(REPLACE " " ";" BUILD_FLAGS_AS_LIST "${${VARNAME}}")
  set(new_flags "")
  foreach (flag ${BUILD_FLAGS_AS_LIST})
    # NOTE: Use of XX here is to avoid a CMake warning due to CMP0054
    if (NOT ("XX${flag}" MATCHES "XX-O[0123s]"))
      set(new_flags "${new_flags} ${flag}")
    else()
      set(new_flags "${new_flags} -O0")
    endif()
  endforeach()
  set(${VARNAME} "${new_flags}")
endforeach()

# Enable the coverage instrumentation (it is disabled for the Fuzzer lib).
set(CMAKE_CXX_FLAGS "${LIBFUZZER_FLAGS_BASE} -fsanitize-coverage=trace-pc-guard,indirect-calls,trace-cmp,trace-div,trace-gep -g")

# add_libfuzzer_test(<name>
#   SOURCES source0.cpp [source1.cpp ...]
#   )
#
#   Declares a LibFuzzer test executable with target name LLVMFuzzer-<name>.
#
#   One or more source files to be compiled into the binary must be declared
#   after the SOURCES keyword.
function(add_libfuzzer_test name)
  set(multi_arg_options "SOURCES")
  cmake_parse_arguments(
    "add_libfuzzer_test" "" "" "${multi_arg_options}" ${ARGN})
  if ("${add_libfuzzer_test_SOURCES}" STREQUAL "")
    message(FATAL_ERROR "Source files must be specified")
  endif()
  add_executable(LLVMFuzzer-${name}
    ${add_libfuzzer_test_SOURCES}
    )
  target_link_libraries(LLVMFuzzer-${name} LLVMFuzzer)
  # Place binary where llvm-lit expects to find it
  set_target_properties(LLVMFuzzer-${name}
    PROPERTIES RUNTIME_OUTPUT_DIRECTORY
    "${CMAKE_BINARY_DIR}/lib/Fuzzer/test"
    )
  set(TestBinaries ${TestBinaries} LLVMFuzzer-${name} PARENT_SCOPE)
endfunction()

# Variable to keep track of all test targets
set(TestBinaries)

###############################################################################
# Basic tests
###############################################################################

set(Tests
  AbsNegAndConstantTest
  AbsNegAndConstant64Test
  AccumulateAllocationsTest
  BufferOverflowOnInput
  CallerCalleeTest
  CounterTest
  CustomCrossOverTest
  CustomMutatorTest
  DivTest
  EmptyTest
  FourIndependentBranchesTest
  FullCoverageSetTest
  InitializeTest
  MemcmpTest
  LeakTest
  LeakTimeoutTest
  LoadTest
  NullDerefTest
  NullDerefOnEmptyTest
  NthRunCrashTest
  OneHugeAllocTest
  OutOfMemoryTest
  OutOfMemorySingleLargeMallocTest
  RepeatedMemcmp
  RepeatedBytesTest
  SimpleCmpTest
  SimpleDictionaryTest
  SimpleHashTest
  SimpleTest
  SimpleThreadedTest
  SingleMemcmpTest
  SingleStrcmpTest
  SingleStrncmpTest
  SpamyTest
  ShrinkControlFlowTest
  ShrinkValueProfileTest
  StrcmpTest
  StrncmpOOBTest
  StrncmpTest
  StrstrTest
  SwapCmpTest
  SwitchTest
  Switch2Test
  ThreadedLeakTest
  ThreadedTest
  TimeoutTest
  TimeoutEmptyTest
  TraceMallocTest
  )

if(APPLE)
  # LeakSanitizer is not supported on OSX right now
  set(HAS_LSAN 0)
  message(WARNING "LeakSanitizer is not supported on Apple platforms."
    " Building and running LibFuzzer LeakSanitizer tests is disabled."
    )
else()
  set(HAS_LSAN 1)
endif()

foreach(Test ${Tests})
  add_libfuzzer_test(${Test} SOURCES ${Test}.cpp)
endforeach()


###############################################################################
# Unit tests
###############################################################################

add_executable(LLVMFuzzer-Unittest
  FuzzerUnittest.cpp
  )

add_executable(LLVMFuzzer-StandaloneInitializeTest
  InitializeTest.cpp
  ../standalone/StandaloneFuzzTargetMain.c
  )

target_link_libraries(LLVMFuzzer-Unittest
  gtest
  gtest_main
  LLVMFuzzerNoMain
  )

target_include_directories(LLVMFuzzer-Unittest PRIVATE
  "${LLVM_MAIN_SRC_DIR}/utils/unittest/googletest/include"
  )

set(TestBinaries ${TestBinaries} LLVMFuzzer-Unittest)
set_target_properties(LLVMFuzzer-Unittest
  PROPERTIES RUNTIME_OUTPUT_DIRECTORY
  "${CMAKE_CURRENT_BINARY_DIR}"
)

set(TestBinaries ${TestBinaries} LLVMFuzzer-StandaloneInitializeTest)
set_target_properties(LLVMFuzzer-StandaloneInitializeTest
  PROPERTIES RUNTIME_OUTPUT_DIRECTORY
  "${CMAKE_CURRENT_BINARY_DIR}"
)

###############################################################################
# Additional tests
###############################################################################

include_directories(..)

# add_subdirectory(uninstrumented)
add_subdirectory(no-coverage)
add_subdirectory(ubsan)

add_library(LLVMFuzzer-DSO1 SHARED DSO1.cpp)
add_library(LLVMFuzzer-DSO2 SHARED DSO2.cpp)

add_executable(LLVMFuzzer-DSOTest
  DSOTestMain.cpp
  DSOTestExtra.cpp)

target_link_libraries(LLVMFuzzer-DSOTest
  LLVMFuzzer-DSO1
  LLVMFuzzer-DSO2
  LLVMFuzzer
  )

set_target_properties(LLVMFuzzer-DSOTest PROPERTIES RUNTIME_OUTPUT_DIRECTORY
  "${CMAKE_BINARY_DIR}/lib/Fuzzer/test")
set_target_properties(LLVMFuzzer-DSO1 PROPERTIES LIBRARY_OUTPUT_DIRECTORY
  "${CMAKE_BINARY_DIR}/lib/Fuzzer/lib")
set_target_properties(LLVMFuzzer-DSO2 PROPERTIES LIBRARY_OUTPUT_DIRECTORY
  "${CMAKE_BINARY_DIR}/lib/Fuzzer/lib")

set(TestBinaries ${TestBinaries} LLVMFuzzer-DSOTest)

###############################################################################
# Configure lit to run the tests
#
# Note this is done after declaring all tests so we can inform lit if any tests
# need to be disabled.
###############################################################################

configure_lit_site_cfg(
  ${CMAKE_CURRENT_SOURCE_DIR}/lit.site.cfg.in
  ${CMAKE_CURRENT_BINARY_DIR}/lit.site.cfg
  )

configure_lit_site_cfg(
  ${CMAKE_CURRENT_SOURCE_DIR}/unit/lit.site.cfg.in
  ${CMAKE_CURRENT_BINARY_DIR}/unit/lit.site.cfg
  )

add_lit_testsuite(check-fuzzer "Running Fuzzer tests"
    ${CMAKE_CURRENT_BINARY_DIR}
    DEPENDS ${TestBinaries} FileCheck not
    )
