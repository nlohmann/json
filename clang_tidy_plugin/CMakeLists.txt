add_library(NlohmannJsonClangTidyPlugin MODULE "")
target_compile_options(NlohmannJsonClangTidyPlugin PRIVATE -fno-rtti)
target_include_directories(NlohmannJsonClangTidyPlugin
    PRIVATE
        ${CLANG_INCLUDE_DIRS}
        ${LLVM_INCLUDE_DIRS}
)
target_sources(NlohmannJsonClangTidyPlugin PRIVATE
  ${CMAKE_CURRENT_LIST_DIR}/Module.cpp
  ${CMAKE_CURRENT_LIST_DIR}/ModernizeNlohmannJsonExplicitConversionsCheck.cpp
)
