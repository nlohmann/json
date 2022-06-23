include("${CMAKE_CURRENT_LIST_DIR}/wflags.cmake")

if(CMAKE_CXX_COMPILER_ID STREQUAL Clang)
    add_compile_options(${CLANG_CXXFLAGS})
elseif(CMAKE_CXX_COMPILER_ID STREQUAL GNU)
    add_compile_options(${GCC_CXXFLAGS})
endif()
