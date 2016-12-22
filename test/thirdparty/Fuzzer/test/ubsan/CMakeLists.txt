# These tests are instrumented with ubsan in non-recovery mode.

set(CMAKE_CXX_FLAGS
  "${LIBFUZZER_FLAGS_BASE} -fsanitize=undefined -fno-sanitize-recover=all")

set(UbsanTests
  SignedIntOverflowTest
  )

foreach(Test ${UbsanTests})
  add_libfuzzer_test(${Test}-Ubsan SOURCES ../${Test}.cpp)
endforeach()

# Propagate value into parent directory
set(TestBinaries ${TestBinaries} PARENT_SCOPE)
