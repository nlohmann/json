set(LIBFUZZER_FLAGS_BASE "${CMAKE_CXX_FLAGS}")
# Disable the coverage and sanitizer instrumentation for the fuzzer itself.
set(CMAKE_CXX_FLAGS "${LIBFUZZER_FLAGS_BASE} -fno-sanitize-coverage=trace-pc-guard,edge,trace-cmp,indirect-calls,8bit-counters -Werror")
if( LLVM_USE_SANITIZE_COVERAGE )
  if(NOT "${LLVM_USE_SANITIZER}" STREQUAL "Address")
    message(FATAL_ERROR
      "LibFuzzer and its tests require LLVM_USE_SANITIZER=Address and "
      "LLVM_USE_SANITIZE_COVERAGE=YES to be set."
      )
  endif()
  add_library(LLVMFuzzerNoMainObjects OBJECT
    FuzzerCrossOver.cpp
    FuzzerDriver.cpp
    FuzzerExtFunctionsDlsym.cpp
    FuzzerExtFunctionsWeak.cpp
    FuzzerExtFunctionsWeakAlias.cpp
    FuzzerIO.cpp
    FuzzerIOPosix.cpp
    FuzzerIOWindows.cpp
    FuzzerLoop.cpp
    FuzzerMerge.cpp
    FuzzerMutate.cpp
    FuzzerSHA1.cpp
    FuzzerTracePC.cpp
    FuzzerTraceState.cpp
    FuzzerUtil.cpp
    FuzzerUtilDarwin.cpp
    FuzzerUtilLinux.cpp
    FuzzerUtilPosix.cpp
    FuzzerUtilWindows.cpp
    )
  add_library(LLVMFuzzerNoMain STATIC
    $<TARGET_OBJECTS:LLVMFuzzerNoMainObjects>
    )
  target_link_libraries(LLVMFuzzerNoMain ${PTHREAD_LIB})
  add_library(LLVMFuzzer STATIC
    FuzzerMain.cpp
    $<TARGET_OBJECTS:LLVMFuzzerNoMainObjects>
    )
  target_link_libraries(LLVMFuzzer ${PTHREAD_LIB})

  if( LLVM_INCLUDE_TESTS )
    add_subdirectory(test)
  endif()
endif()
