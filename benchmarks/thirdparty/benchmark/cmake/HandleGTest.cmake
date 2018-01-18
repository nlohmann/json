
macro(split_list listname)
  string(REPLACE ";" " " ${listname} "${${listname}}")
endmacro()

macro(build_external_gtest)
  include(ExternalProject)
  set(GTEST_FLAGS "")
  if (BENCHMARK_USE_LIBCXX)
    if ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
      list(APPEND GTEST_FLAGS -stdlib=libc++)
    else()
      message(WARNING "Unsupported compiler (${CMAKE_CXX_COMPILER}) when using libc++")
    endif()
  endif()
  if (BENCHMARK_BUILD_32_BITS)
    list(APPEND GTEST_FLAGS -m32)
  endif()
  if (NOT "${CMAKE_CXX_FLAGS}" STREQUAL "")
    list(APPEND GTEST_FLAGS ${CMAKE_CXX_FLAGS})
  endif()
  string(TOUPPER "${CMAKE_BUILD_TYPE}" GTEST_BUILD_TYPE)
  if ("${GTEST_BUILD_TYPE}" STREQUAL "COVERAGE")
    set(GTEST_BUILD_TYPE "DEBUG")
  endif()
  split_list(GTEST_FLAGS)
  ExternalProject_Add(googletest
      EXCLUDE_FROM_ALL ON
      GIT_REPOSITORY https://github.com/google/googletest.git
      GIT_TAG master
      PREFIX "${CMAKE_BINARY_DIR}/googletest"
      INSTALL_DIR "${CMAKE_BINARY_DIR}/googletest"
      CMAKE_CACHE_ARGS
        -DCMAKE_BUILD_TYPE:STRING=${GTEST_BUILD_TYPE}
        -DCMAKE_C_COMPILER:STRING=${CMAKE_C_COMPILER}
        -DCMAKE_CXX_COMPILER:STRING=${CMAKE_CXX_COMPILER}
        -DCMAKE_INSTALL_PREFIX:PATH=<INSTALL_DIR>
        -DCMAKE_CXX_FLAGS:STRING=${GTEST_FLAGS}
        -Dgtest_force_shared_crt:BOOL=ON
      )

  ExternalProject_Get_Property(googletest install_dir)

  add_library(gtest UNKNOWN IMPORTED)
  add_library(gtest_main UNKNOWN IMPORTED)

  set(LIB_SUFFIX "${CMAKE_STATIC_LIBRARY_SUFFIX}")
  set(LIB_PREFIX "${CMAKE_STATIC_LIBRARY_PREFIX}")

  if("${GTEST_BUILD_TYPE}" STREQUAL "DEBUG")
    set(LIB_SUFFIX "d${CMAKE_STATIC_LIBRARY_SUFFIX}")
  endif()
  file(MAKE_DIRECTORY ${install_dir}/include)
  set_target_properties(gtest PROPERTIES
    IMPORTED_LOCATION ${install_dir}/lib/${LIB_PREFIX}gtest${LIB_SUFFIX}
    INTERFACE_INCLUDE_DIRECTORIES ${install_dir}/include
  )
  set_target_properties(gtest_main PROPERTIES
    IMPORTED_LOCATION ${install_dir}/lib/${LIB_PREFIX}gtest_main${LIB_SUFFIX}
    INTERFACE_INCLUDE_DIRECTORIES ${install_dir}/include
  )
  add_dependencies(gtest googletest)
  add_dependencies(gtest_main googletest)
  set(GTEST_BOTH_LIBRARIES gtest gtest_main)
  #set(GTEST_INCLUDE_DIRS ${install_dir}/include)
endmacro(build_external_gtest)

if (BENCHMARK_ENABLE_GTEST_TESTS)
  if (IS_DIRECTORY ${CMAKE_SOURCE_DIR}/googletest)
    set(INSTALL_GTEST OFF CACHE INTERNAL "")
    set(INSTALL_GMOCK OFF CACHE INTERNAL "")
    add_subdirectory(${CMAKE_SOURCE_DIR}/googletest)
    set(GTEST_BOTH_LIBRARIES gtest gtest_main)
  elseif(BENCHMARK_DOWNLOAD_DEPENDENCIES)
    build_external_gtest()
  else()
    find_package(GTest REQUIRED)
  endif()
endif()
