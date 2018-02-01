include(FeatureSummary)

find_program(LLVMNM_EXECUTABLE
  NAMES llvm-nm
  DOC "The llvm-nm executable"
  )

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(LLVMNm
  DEFAULT_MSG
  LLVMNM_EXECUTABLE)

SET_PACKAGE_PROPERTIES(LLVMNm PROPERTIES
  URL https://llvm.org/docs/CommandGuide/llvm-nm.html
  DESCRIPTION "list LLVM bitcode and object file’s symbol table"
)
