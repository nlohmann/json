include(FeatureSummary)

find_program(LLVMRANLIB_EXECUTABLE
  NAMES llvm-ranlib
  DOC "The llvm-ranlib executable"
  )

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(LLVMRanLib
  DEFAULT_MSG
  LLVMRANLIB_EXECUTABLE)

SET_PACKAGE_PROPERTIES(LLVMRanLib PROPERTIES
  DESCRIPTION "generate index for LLVM archive"
)
