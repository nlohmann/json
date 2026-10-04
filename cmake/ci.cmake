# number of parallel jobs for CTest
set(N 10)

###############################################################################
# Needed tools.
###############################################################################

include(FindPython3)
find_package(Python3 COMPONENTS Interpreter)

find_program(CLANG_TOOL NAMES clang++-HEAD clang++ clang++-22 clang++-21 clang++-20 clang++-19 clang++-18 clang++-17 clang++-16 clang++-15 clang++-14 clang++-13 clang++-12 clang++-11 clang++)
execute_process(COMMAND ${CLANG_TOOL} --version OUTPUT_VARIABLE CLANG_TOOL_VERSION ERROR_VARIABLE CLANG_TOOL_VERSION)
string(REGEX MATCH "[0-9]+(\\.[0-9]+)+" CLANG_TOOL_VERSION "${CLANG_TOOL_VERSION}")
message(STATUS "🔖 Clang ${CLANG_TOOL_VERSION} (${CLANG_TOOL})")

find_program(CLANG_TIDY_TOOL NAMES clang-tidy-22 clang-tidy-21 clang-tidy-20 clang-tidy-19 clang-tidy-18 clang-tidy-17 clang-tidy-16 clang-tidy-15 clang-tidy-14 clang-tidy-13 clang-tidy-12 clang-tidy-11 clang-tidy)
execute_process(COMMAND ${CLANG_TIDY_TOOL} --version OUTPUT_VARIABLE CLANG_TIDY_TOOL_VERSION ERROR_VARIABLE CLANG_TIDY_TOOL_VERSION)
string(REGEX MATCH "[0-9]+(\\.[0-9]+)+" CLANG_TIDY_TOOL_VERSION "${CLANG_TIDY_TOOL_VERSION}")
message(STATUS "🔖 Clang-Tidy ${CLANG_TIDY_TOOL_VERSION} (${CLANG_TIDY_TOOL})")

message(STATUS "🔖 CMake ${CMAKE_VERSION} (${CMAKE_COMMAND})")

find_program(GCC_TOOL NAMES g++-latest g++-HEAD g++ g++-16 g++-15 g++-14 g++-13 g++-12 g++-11 g++-10)
execute_process(COMMAND ${GCC_TOOL} --version OUTPUT_VARIABLE GCC_TOOL_VERSION ERROR_VARIABLE GCC_TOOL_VERSION)
string(REGEX MATCH "[0-9]+(\\.[0-9]+)+" GCC_TOOL_VERSION "${GCC_TOOL_VERSION}")
message(STATUS "🔖 GCC ${GCC_TOOL_VERSION} (${GCC_TOOL})")

find_program(GCOV_TOOL NAMES gcov-HEAD gcov gcov-16 gcov-15 gcov-14 gcov-13 gcov-12 gcov-11 gcov-10)
execute_process(COMMAND ${GCOV_TOOL} --version OUTPUT_VARIABLE GCOV_TOOL_VERSION ERROR_VARIABLE GCOV_TOOL_VERSION)
string(REGEX MATCH "[0-9]+(\\.[0-9]+)+" GCOV_TOOL_VERSION "${GCOV_TOOL_VERSION}")
message(STATUS "🔖 GCOV ${GCOV_TOOL_VERSION} (${GCOV_TOOL})")

find_program(GIT_TOOL NAMES git)
execute_process(COMMAND ${GIT_TOOL} --version OUTPUT_VARIABLE GIT_TOOL_VERSION ERROR_VARIABLE GIT_TOOL_VERSION)
string(REGEX MATCH "[0-9]+(\\.[0-9]+)+" GIT_TOOL_VERSION "${GIT_TOOL_VERSION}")
message(STATUS "🔖 Git ${GIT_TOOL_VERSION} (${GIT_TOOL})")

find_program(IWYU_TOOL NAMES include-what-you-use iwyu)
execute_process(COMMAND ${IWYU_TOOL} --version OUTPUT_VARIABLE IWYU_TOOL_VERSION ERROR_VARIABLE IWYU_TOOL_VERSION)
string(REGEX MATCH "[0-9]+(\\.[0-9]+)+" IWYU_TOOL_VERSION "${IWYU_TOOL_VERSION}")
message(STATUS "🔖 include-what-you-use ${IWYU_TOOL_VERSION} (${IWYU_TOOL})")

# CMake's CXX_INCLUDE_WHAT_YOU_USE launcher runs IWYU during the normal compile step (useful to see
# diagnostics inline), but CMake's own __run_co_compile wrapper does not propagate the launched
# tool's exit code to the build, so IWYU's own "-Xiwyu --error" cannot fail that step (verified: a
# deliberately-unused #include in a header still lets `cmake --build` finish with exit code 0).
# iwyu_tool.py, which ships with IWYU, reads compile_commands.json and does return a non-zero exit
# code for any analyzed file with findings; ci_single_binaries uses it to actually fail on findings.
find_program(IWYU_TOOL_PY NAMES iwyu_tool iwyu_tool.py iwyu-tool)

find_program(INFER_TOOL NAMES infer)
execute_process(COMMAND ${INFER_TOOL} --version OUTPUT_VARIABLE INFER_TOOL_VERSION ERROR_VARIABLE INFER_TOOL_VERSION)
string(REGEX MATCH "[0-9]+(\\.[0-9]+)+" INFER_TOOL_VERSION "${INFER_TOOL_VERSION}")
message(STATUS "🔖 Infer ${INFER_TOOL_VERSION} (${INFER_TOOL})")

find_program(LCOV_TOOL NAMES lcov)
execute_process(COMMAND ${LCOV_TOOL} --version OUTPUT_VARIABLE LCOV_TOOL_VERSION ERROR_VARIABLE LCOV_TOOL_VERSION)
string(REGEX MATCH "[0-9]+(\\.[0-9]+)+" LCOV_TOOL_VERSION "${LCOV_TOOL_VERSION}")
message(STATUS "🔖 LCOV ${LCOV_TOOL_VERSION} (${LCOV_TOOL})")

find_program(NINJA_TOOL NAMES ninja)
execute_process(COMMAND ${NINJA_TOOL} --version OUTPUT_VARIABLE NINJA_TOOL_VERSION ERROR_VARIABLE NINJA_TOOL_VERSION)
string(REGEX MATCH "[0-9]+(\\.[0-9]+)+" NINJA_TOOL_VERSION "${NINJA_TOOL_VERSION}")
message(STATUS "🔖 Ninja ${NINJA_TOOL_VERSION} (${NINJA_TOOL})")

find_program(VALGRIND_TOOL NAMES valgrind)
execute_process(COMMAND ${VALGRIND_TOOL} --version OUTPUT_VARIABLE VALGRIND_TOOL_VERSION ERROR_VARIABLE VALGRIND_TOOL_VERSION)
string(REGEX MATCH "[0-9]+(\\.[0-9]+)+" VALGRIND_TOOL_VERSION "${VALGRIND_TOOL_VERSION}")
message(STATUS "🔖 Valgrind ${VALGRIND_TOOL_VERSION} (${VALGRIND_TOOL})")

find_program(GENHTML_TOOL NAMES genhtml)
find_program(PLOG_CONVERTER_TOOL NAMES plog-converter)
find_program(PVS_STUDIO_ANALYZER_TOOL NAMES pvs-studio-analyzer)
find_program(SCAN_BUILD_TOOL NAMES scan-build-15 scan-build-14 scan-build-13 scan-build-12 scan-build-11 scan-build)

# the individual source files
file(GLOB_RECURSE SRC_FILES ${PROJECT_SOURCE_DIR}/include/nlohmann/*.hpp)

###############################################################################
# Thorough check with recent compilers
###############################################################################

include(clang_flags)
include(gcc_flags)

add_custom_target(ci_test_gcc
    COMMAND CXX=${GCC_TOOL} CXXFLAGS="${GCC_CXXFLAGS}" ${CMAKE_COMMAND}
        -DCMAKE_BUILD_TYPE=Debug -GNinja
        -DJSON_BuildTests=ON
        -S${PROJECT_SOURCE_DIR} -B${PROJECT_BINARY_DIR}/build_gcc
    COMMAND ${CMAKE_COMMAND} --build ${PROJECT_BINARY_DIR}/build_gcc
    COMMAND cd ${PROJECT_BINARY_DIR}/build_gcc && ${CMAKE_CTEST_COMMAND} --parallel ${N} --output-on-failure
    COMMENT "Compile and test with GCC using maximal warning flags"
)

add_custom_target(ci_test_clang
    COMMAND CXX=${CLANG_TOOL} CXXFLAGS="${CLANG_CXXFLAGS}" ${CMAKE_COMMAND}
        -DCMAKE_BUILD_TYPE=Debug -GNinja
        -DJSON_BuildTests=ON
        -S${PROJECT_SOURCE_DIR} -B${PROJECT_BINARY_DIR}/build_clang
    COMMAND ${CMAKE_COMMAND} --build ${PROJECT_BINARY_DIR}/build_clang
    COMMAND cd ${PROJECT_BINARY_DIR}/build_clang && ${CMAKE_CTEST_COMMAND} --parallel ${N} --output-on-failure
    COMMENT "Compile and test with Clang using maximal warning flags"
)

###############################################################################
# Different C++ Standards.
###############################################################################

foreach(CXX_STANDARD 11 14 17 20 23 26)
    add_custom_target(ci_test_gcc_cxx${CXX_STANDARD}
        COMMAND CXX=${GCC_TOOL} CXXFLAGS="${GCC_CXXFLAGS}" ${CMAKE_COMMAND}
            -DCMAKE_BUILD_TYPE=Debug -GNinja
            -DJSON_BuildTests=ON -DJSON_FastTests=ON
            -DJSON_TestStandards=${CXX_STANDARD}
            -S${PROJECT_SOURCE_DIR} -B${PROJECT_BINARY_DIR}/build_gcc_cxx${CXX_STANDARD}
        COMMAND ${CMAKE_COMMAND} --build ${PROJECT_BINARY_DIR}/build_gcc_cxx${CXX_STANDARD}
        COMMAND cd ${PROJECT_BINARY_DIR}/build_gcc_cxx${CXX_STANDARD} && ${CMAKE_CTEST_COMMAND} --parallel ${N} --output-on-failure
        COMMENT "Compile and test with GCC for C++${CXX_STANDARD}"
    )

    add_custom_target(ci_test_clang_cxx${CXX_STANDARD}
        COMMAND CXX=${CLANG_TOOL} CXXFLAGS="${CLANG_CXXFLAGS}" ${CMAKE_COMMAND}
            -DCMAKE_BUILD_TYPE=Debug -GNinja
            -DJSON_BuildTests=ON -DJSON_FastTests=ON
            -DJSON_TestStandards=${CXX_STANDARD}
            -S${PROJECT_SOURCE_DIR} -B${PROJECT_BINARY_DIR}/build_clang_cxx${CXX_STANDARD}
        COMMAND ${CMAKE_COMMAND} --build ${PROJECT_BINARY_DIR}/build_clang_cxx${CXX_STANDARD}
        COMMAND cd ${PROJECT_BINARY_DIR}/build_clang_cxx${CXX_STANDARD} && ${CMAKE_CTEST_COMMAND} --parallel ${N} --output-on-failure
        COMMENT "Compile and test with Clang for C++${CXX_STANDARD}"
    )

    # pass -stdlib=libc++ through CXXFLAGS: an explicit -DCMAKE_CXX_FLAGS would make CMake ignore CXXFLAGS
    add_custom_target(ci_test_clang_libcxx_cxx${CXX_STANDARD}
        COMMAND CXX=${CLANG_TOOL} CXXFLAGS="${CLANG_CXXFLAGS};-stdlib=libc++" ${CMAKE_COMMAND}
            -DCMAKE_BUILD_TYPE=Debug -GNinja
            -DJSON_BuildTests=ON -DJSON_FastTests=ON
            -DJSON_TestStandards=${CXX_STANDARD}
            -DCMAKE_EXE_LINKER_FLAGS="-lc++abi"
            -S${PROJECT_SOURCE_DIR} -B${PROJECT_BINARY_DIR}/build_clang_libcxx_cxx${CXX_STANDARD}
        COMMAND ${CMAKE_COMMAND} --build ${PROJECT_BINARY_DIR}/build_clang_libcxx_cxx${CXX_STANDARD}
        COMMAND cd ${PROJECT_BINARY_DIR}/build_clang_libcxx_cxx${CXX_STANDARD} && ${CMAKE_CTEST_COMMAND} --parallel ${N} --output-on-failure
        COMMENT "Compile and test with Clang for C++${CXX_STANDARD} (libc++)"
    )
endforeach()

###############################################################################
# Disable exceptions.
###############################################################################

add_custom_target(ci_test_noexceptions
    COMMAND ${CMAKE_COMMAND}
    -DCMAKE_BUILD_TYPE=Debug -GNinja
    -DJSON_BuildTests=ON -DCMAKE_CXX_FLAGS=-DJSON_NOEXCEPTION -DDOCTEST_TEST_FILTER=--no-throw
    -S${PROJECT_SOURCE_DIR} -B${PROJECT_BINARY_DIR}/build_noexceptions
    COMMAND ${CMAKE_COMMAND} --build ${PROJECT_BINARY_DIR}/build_noexceptions
    COMMAND cd ${PROJECT_BINARY_DIR}/build_noexceptions && ${CMAKE_CTEST_COMMAND} --parallel ${N} --output-on-failure
    COMMENT "Compile and test with exceptions switched off"
)

###############################################################################
# Disable implicit conversions.
###############################################################################

add_custom_target(ci_test_noimplicitconversions
    COMMAND ${CMAKE_COMMAND}
    -DCMAKE_BUILD_TYPE=Debug -GNinja
    -DJSON_BuildTests=ON -DJSON_ImplicitConversions=OFF
    -S${PROJECT_SOURCE_DIR} -B${PROJECT_BINARY_DIR}/build_noimplicitconversions
    COMMAND ${CMAKE_COMMAND} --build ${PROJECT_BINARY_DIR}/build_noimplicitconversions
    COMMAND cd ${PROJECT_BINARY_DIR}/build_noimplicitconversions && ${CMAKE_CTEST_COMMAND} --parallel ${N} --output-on-failure
    COMMENT "Compile and test with implicit conversions switched off"
)

###############################################################################
# Enable improved diagnostics.
###############################################################################

add_custom_target(ci_test_diagnostics
    COMMAND ${CMAKE_COMMAND}
    -DCMAKE_BUILD_TYPE=Debug -GNinja
    -DJSON_BuildTests=ON -DJSON_Diagnostics=ON
    -S${PROJECT_SOURCE_DIR} -B${PROJECT_BINARY_DIR}/build_diagnostics
    COMMAND ${CMAKE_COMMAND} --build ${PROJECT_BINARY_DIR}/build_diagnostics
    COMMAND cd ${PROJECT_BINARY_DIR}/build_diagnostics && ${CMAKE_CTEST_COMMAND} --parallel ${N} --output-on-failure
    COMMENT "Compile and test with improved diagnostics enabled"
)

###############################################################################
# Enable diagnostic positions support.
###############################################################################

add_custom_target(ci_test_diagnostic_positions
    COMMAND ${CMAKE_COMMAND}
    -DCMAKE_BUILD_TYPE=Debug -GNinja
    -DJSON_BuildTests=ON -DJSON_Diagnostic_Positions=ON
    -S${PROJECT_SOURCE_DIR} -B${PROJECT_BINARY_DIR}/build_diagnostic_positions
    COMMAND ${CMAKE_COMMAND} --build ${PROJECT_BINARY_DIR}/build_diagnostic_positions
    COMMAND cd ${PROJECT_BINARY_DIR}/build_diagnostic_positions && ${CMAKE_CTEST_COMMAND} --parallel ${N} --output-on-failure
    COMMENT "Compile and test with diagnostic positions enabled"
)

###############################################################################
# Enable legacy discarded value comparison.
###############################################################################

add_custom_target(ci_test_legacycomparison
    COMMAND ${CMAKE_COMMAND}
    -DCMAKE_BUILD_TYPE=Debug -GNinja
    -DJSON_BuildTests=ON -DJSON_LegacyDiscardedValueComparison=ON
    -S${PROJECT_SOURCE_DIR} -B${PROJECT_BINARY_DIR}/build_legacycomparison
    COMMAND ${CMAKE_COMMAND} --build ${PROJECT_BINARY_DIR}/build_legacycomparison
    COMMAND cd ${PROJECT_BINARY_DIR}/build_legacycomparison && ${CMAKE_CTEST_COMMAND} --parallel ${N} --output-on-failure
    COMMENT "Compile and test with legacy discarded value comparison enabled"
)

###############################################################################
# Validate UTF-8 with simdutf.
###############################################################################

add_custom_target(ci_test_simdutf
    COMMAND ${CMAKE_COMMAND}
    -DCMAKE_BUILD_TYPE=Debug -GNinja
    -DJSON_BuildTests=ON -DJSON_TestSimdutf=ON
    # simdutf needs C++17, so the library falls back to its scalar validator
    # below that: build the suite at C++11 to cover the fallback with the macro
    # defined, and at C++17 to run every test against simdutf itself
    "-DJSON_TestStandards=11\;17"
    -S${PROJECT_SOURCE_DIR} -B${PROJECT_BINARY_DIR}/build_simdutf
    COMMAND ${CMAKE_COMMAND} --build ${PROJECT_BINARY_DIR}/build_simdutf
    COMMAND cd ${PROJECT_BINARY_DIR}/build_simdutf && ${CMAKE_CTEST_COMMAND} --parallel ${N} --output-on-failure
    COMMENT "Compile and test with simdutf UTF-8 validation enabled"
)

###############################################################################
# Enable strict NUL-byte handling.
###############################################################################

add_custom_target(ci_test_strict_nul_handling
    COMMAND ${CMAKE_COMMAND}
    -DCMAKE_BUILD_TYPE=Debug -GNinja
    -DJSON_BuildTests=ON -DJSON_FastTests=ON -DJSON_StrictNulHandling=ON
    -S${PROJECT_SOURCE_DIR} -B${PROJECT_BINARY_DIR}/build_strict_nul_handling
    COMMAND ${CMAKE_COMMAND} --build ${PROJECT_BINARY_DIR}/build_strict_nul_handling
    # unit-testsuites contains a fixture (a "1e308" test value) that relies on the
    # legacy NUL-as-end-of-input behavior this macro disables; exclude it here, as
    # it is expected to fail under strict NUL handling and is out of scope for it
    COMMAND cd ${PROJECT_BINARY_DIR}/build_strict_nul_handling && ${CMAKE_CTEST_COMMAND} --parallel ${N} --output-on-failure -E "test-testsuites"
    COMMENT "Compile and test with strict NUL-byte handling enabled"
)

###############################################################################
# Disable global UDLs.
###############################################################################

add_custom_target(ci_test_noglobaludls
    COMMAND ${CMAKE_COMMAND}
    -DCMAKE_BUILD_TYPE=Debug -GNinja
    -DJSON_BuildTests=ON -DJSON_FastTests=ON -DJSON_GlobalUDLs=OFF
    -DCMAKE_CXX_FLAGS=-DJSON_TEST_NO_GLOBAL_UDLS
    -S${PROJECT_SOURCE_DIR} -B${PROJECT_BINARY_DIR}/build_noglobaludls
    COMMAND ${CMAKE_COMMAND} --build ${PROJECT_BINARY_DIR}/build_noglobaludls
    COMMAND cd ${PROJECT_BINARY_DIR}/build_noglobaludls && ${CMAKE_CTEST_COMMAND} --parallel ${N} --output-on-failure
    COMMENT "Compile and test with global UDLs disabled"
)

###############################################################################
# Disable enum serialization.
###############################################################################

add_custom_target(ci_test_disableenumserialization
    COMMAND ${CMAKE_COMMAND}
    -DCMAKE_BUILD_TYPE=Debug -GNinja
    -DJSON_BuildTests=ON -DJSON_FastTests=ON -DJSON_DisableEnumSerialization=ON
    -S${PROJECT_SOURCE_DIR} -B${PROJECT_BINARY_DIR}/build_disableenumserialization
    COMMAND ${CMAKE_COMMAND} --build ${PROJECT_BINARY_DIR}/build_disableenumserialization
    COMMAND cd ${PROJECT_BINARY_DIR}/build_disableenumserialization && ${CMAKE_CTEST_COMMAND} --parallel ${N} --output-on-failure
    COMMENT "Compile and test with enum serialization disabled"
)

###############################################################################
# Disable conversion from a one-element tuple of a JSON reference.
###############################################################################

add_custom_target(ci_test_disabletuplereferenceconversion
    COMMAND ${CMAKE_COMMAND}
    -DCMAKE_BUILD_TYPE=Debug -GNinja
    -DJSON_BuildTests=ON -DJSON_FastTests=ON -DJSON_DisableTupleReferenceConversion=ON
    -S${PROJECT_SOURCE_DIR} -B${PROJECT_BINARY_DIR}/build_disabletuplereferenceconversion
    COMMAND ${CMAKE_COMMAND} --build ${PROJECT_BINARY_DIR}/build_disabletuplereferenceconversion
    COMMAND cd ${PROJECT_BINARY_DIR}/build_disabletuplereferenceconversion && ${CMAKE_CTEST_COMMAND} --parallel ${N} --output-on-failure
    COMMENT "Compile and test with tuple reference conversion disabled"
)

###############################################################################
# Skip the multiple-inclusion library version check.
###############################################################################

# tests/src/skip_library_version_check.cpp deliberately simulates a scenario
# (mixing two differently-versioned inclusions of the library in one
# translation unit) that unavoidably triggers the compiler's own "macro
# redefined" warning, so -- unlike the ci_test_* targets above -- it is
# compiled directly here, with a modest warning set, instead of being folded
# into the library's own -Weverything/-Werror unit test matrix.
add_custom_target(ci_test_skiplibraryversioncheck
    COMMAND ${CMAKE_COMMAND} -E make_directory ${PROJECT_BINARY_DIR}/skip_library_version_check
    COMMAND ${CMAKE_CXX_COMPILER} -std=c++11 -Wall -Wextra
        -I${PROJECT_SOURCE_DIR}/include
        ${PROJECT_SOURCE_DIR}/tests/src/skip_library_version_check.cpp
        -o ${PROJECT_BINARY_DIR}/skip_library_version_check/skip_library_version_check
    COMMAND ${PROJECT_BINARY_DIR}/skip_library_version_check/skip_library_version_check
    COMMENT "Compile and run a translation unit simulating a mismatched library version, with JSON_SKIP_LIBRARY_VERSION_CHECK defined"
)

###############################################################################
# Disable thread-local storage.
###############################################################################

# Without thread-local storage, copying and comparing cannot bound their
# descent and handle every object and array without the call stack. Those paths
# are otherwise only reached by values nested deeper than the bound, so this
# target is what runs the whole test suite through them.
add_custom_target(ci_test_no_thread_local
    COMMAND ${CMAKE_COMMAND}
    -DCMAKE_BUILD_TYPE=Debug -GNinja
    -DJSON_BuildTests=ON
    -DCMAKE_CXX_FLAGS=-DJSON_NO_THREAD_LOCAL
    -S${PROJECT_SOURCE_DIR} -B${PROJECT_BINARY_DIR}/build_no_thread_local
    COMMAND ${CMAKE_COMMAND} --build ${PROJECT_BINARY_DIR}/build_no_thread_local
    COMMAND cd ${PROJECT_BINARY_DIR}/build_no_thread_local && ${CMAKE_CTEST_COMMAND} --parallel ${N} --output-on-failure
    COMMENT "Compile and test without thread-local storage"
)

###############################################################################
# Coverage.
###############################################################################

add_custom_target(ci_test_coverage
    COMMAND CXX=g++ ${CMAKE_COMMAND}
        -DCMAKE_BUILD_TYPE=Debug -GNinja -DCMAKE_CXX_FLAGS="--coverage;-fprofile-arcs;-ftest-coverage"
        -DJSON_BuildTests=ON
        -S${PROJECT_SOURCE_DIR} -B${PROJECT_BINARY_DIR}/build_coverage
    COMMAND ${CMAKE_COMMAND} --build ${PROJECT_BINARY_DIR}/build_coverage
    COMMAND cd ${PROJECT_BINARY_DIR}/build_coverage && ${CMAKE_CTEST_COMMAND} --parallel ${N} --output-on-failure

    COMMAND CXX=g++ ${CMAKE_COMMAND}
        -DCMAKE_BUILD_TYPE=Debug -GNinja -DCMAKE_CXX_FLAGS="-m32;--coverage;-fprofile-arcs;-ftest-coverage"
        -DJSON_BuildTests=ON -DJSON_32bitTest=ONLY
        -S${PROJECT_SOURCE_DIR} -B${PROJECT_BINARY_DIR}/build_coverage32
    COMMAND ${CMAKE_COMMAND} --build ${PROJECT_BINARY_DIR}/build_coverage32
    COMMAND cd ${PROJECT_BINARY_DIR}/build_coverage32 && ${CMAKE_CTEST_COMMAND} --parallel ${N} --output-on-failure

    COMMAND ${LCOV_TOOL} --directory . --capture --output-file json.info --rc branch_coverage=1 --rc geninfo_unexecuted_blocks=1 --ignore-errors mismatch --ignore-errors unused
    COMMAND ${LCOV_TOOL} -e json.info ${SRC_FILES} --output-file json.info.filtered --rc branch_coverage=1 --ignore-errors unused
    COMMAND ${CMAKE_SOURCE_DIR}/tests/thirdparty/imapdl/filterbr.py json.info.filtered > json.info.filtered.noexcept
    COMMAND genhtml --title "JSON for Modern C++" --legend --demangle-cpp --output-directory html --show-details --branch-coverage json.info.filtered.noexcept

    COMMENT "Compile and test with coverage"
)

###############################################################################
# Sanitizers.
###############################################################################

set(CLANG_CXX_FLAGS_SANITIZER "-g -O1 -fsanitize=address -fsanitize=undefined -fsanitize=integer -fsanitize=nullability -fno-omit-frame-pointer -fno-sanitize-recover=all -fno-sanitize=unsigned-integer-overflow -fno-sanitize=unsigned-shift-base")

add_custom_target(ci_test_clang_sanitizer
    COMMAND CXX=${CLANG_TOOL} CXXFLAGS=${CLANG_CXX_FLAGS_SANITIZER} ${CMAKE_COMMAND}
        -DCMAKE_BUILD_TYPE=Debug -GNinja
        -DJSON_BuildTests=ON
        -S${PROJECT_SOURCE_DIR} -B${PROJECT_BINARY_DIR}/build_clang_sanitizer
    COMMAND ${CMAKE_COMMAND} --build ${PROJECT_BINARY_DIR}/build_clang_sanitizer
    COMMAND cd ${PROJECT_BINARY_DIR}/build_clang_sanitizer && ${CMAKE_CTEST_COMMAND} --parallel ${N} --output-on-failure
    COMMENT "Compile and test with sanitizers"
)

###############################################################################
# Check if header is amalgamated and sources are properly indented.
###############################################################################

# Same file set as .github/workflows/check_amalgamation.yml, so a direct push to develop/master/release/*
# (which only this CMake target checks, not the pull_request-only workflow) is held to the same standard.
file(GLOB_RECURSE INDENT_FILES
    ${PROJECT_SOURCE_DIR}/docs/mkdocs/docs/examples/*.hpp
    ${PROJECT_SOURCE_DIR}/docs/mkdocs/docs/examples/*.cpp
    ${PROJECT_SOURCE_DIR}/docs/mkdocs/docs/examples/*.cu
    ${PROJECT_SOURCE_DIR}/include/*.hpp
    ${PROJECT_SOURCE_DIR}/include/*.cpp
    ${PROJECT_SOURCE_DIR}/include/*.cu
    ${PROJECT_SOURCE_DIR}/tests/*.hpp
    ${PROJECT_SOURCE_DIR}/tests/*.cpp
    ${PROJECT_SOURCE_DIR}/tests/*.cu
)
list(FILTER INDENT_FILES EXCLUDE REGEX "/tests/thirdparty/|/tests/abi/include/nlohmann/")

set(include_dir ${PROJECT_SOURCE_DIR}/single_include/nlohmann)
set(tool_dir ${PROJECT_SOURCE_DIR}/tools/amalgamate)
add_custom_target(ci_test_amalgamation
    COMMAND rm -fr ${include_dir}/json.hpp~ ${include_dir}/json_fwd.hpp~ ${include_dir}/json_literals.hpp~
    COMMAND cp ${include_dir}/json.hpp ${include_dir}/json.hpp~
    COMMAND cp ${include_dir}/json_fwd.hpp ${include_dir}/json_fwd.hpp~
    COMMAND cp ${include_dir}/json_literals.hpp ${include_dir}/json_literals.hpp~
    COMMAND cp ${PROJECT_SOURCE_DIR}/BUILD.bazel ${PROJECT_SOURCE_DIR}/BUILD.bazel~

    COMMAND ${Python3_EXECUTABLE} -mvenv venv_astyle
    COMMAND venv_astyle/bin/pip3 --quiet install -r ${CMAKE_SOURCE_DIR}/tools/astyle/requirements.txt
    COMMAND venv_astyle/bin/astyle --version

    COMMAND ${Python3_EXECUTABLE} ${tool_dir}/amalgamate.py -c ${tool_dir}/config_json.json -s .
    COMMAND ${Python3_EXECUTABLE} ${tool_dir}/amalgamate.py -c ${tool_dir}/config_json_fwd.json -s .
    COMMAND cp ${PROJECT_SOURCE_DIR}/include/nlohmann/json_literals.hpp ${include_dir}/json_literals.hpp
    COMMAND venv_astyle/bin/astyle --project=tools/astyle/.astylerc --suffix=none ${include_dir}/json.hpp ${include_dir}/json_fwd.hpp
    COMMAND ${CMAKE_COMMAND} -P ${PROJECT_SOURCE_DIR}/cmake/scripts/gen_bazel_build_file.cmake

    COMMAND diff ${include_dir}/json.hpp~ ${include_dir}/json.hpp
    COMMAND diff ${include_dir}/json_fwd.hpp~ ${include_dir}/json_fwd.hpp
    COMMAND diff ${include_dir}/json_literals.hpp~ ${include_dir}/json_literals.hpp
    COMMAND diff ${PROJECT_SOURCE_DIR}/BUILD.bazel~ ${PROJECT_SOURCE_DIR}/BUILD.bazel

    COMMAND venv_astyle/bin/astyle --project=tools/astyle/.astylerc --suffix=orig ${INDENT_FILES}
    COMMAND for FILE in `find . -name '*.orig'`\; do false \; done

    WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
    COMMENT "Check amalgamation, formatting, and BUILD.bazel"
)

###############################################################################
# Build and test using the amalgamated header
###############################################################################

add_custom_target(ci_test_single_header
    COMMAND ${CMAKE_COMMAND}
        -DCMAKE_BUILD_TYPE=Debug -GNinja
        -DJSON_BuildTests=ON -DJSON_MultipleHeaders=OFF -DJSON_FastTests=ON
        -S${PROJECT_SOURCE_DIR} -B${PROJECT_BINARY_DIR}/build_single_header
    COMMAND ${CMAKE_COMMAND} --build ${PROJECT_BINARY_DIR}/build_single_header
    COMMAND cd ${PROJECT_BINARY_DIR}/build_single_header && ${CMAKE_CTEST_COMMAND} --parallel ${N} --output-on-failure
    COMMENT "Compile and test single-header version"
)

###############################################################################
# Valgrind.
###############################################################################

add_custom_target(ci_test_valgrind
    COMMAND CXX=${GCC_TOOL} ${CMAKE_COMMAND}
        -DCMAKE_BUILD_TYPE=Debug -GNinja
        -DJSON_BuildTests=ON -DJSON_Valgrind=ON
        -S${PROJECT_SOURCE_DIR} -B${PROJECT_BINARY_DIR}/build_valgrind
    COMMAND ${CMAKE_COMMAND} --build ${PROJECT_BINARY_DIR}/build_valgrind
    COMMAND cd ${PROJECT_BINARY_DIR}/build_valgrind && ${CMAKE_CTEST_COMMAND} -L valgrind --parallel ${N} --output-on-failure
    COMMENT "Compile and test with Valgrind"
)

###############################################################################
# Check code with Clang Static Analyzer.
###############################################################################

set(CLANG_ANALYZER_CHECKS "nullability.NullableDereferenced,nullability.NullablePassedToNonnull,nullability.NullableReturnedFromNonnull,optin.cplusplus.UninitializedObject,optin.cplusplus.VirtualCall,optin.performance.Padding,optin.portability.UnixAPI,security.FloatLoopCounter,security.insecureAPI.DeprecatedOrUnsafeBufferHandling,security.insecureAPI.bcmp,security.insecureAPI.bcopy,security.insecureAPI.bzero,security.insecureAPI.rand,security.insecureAPI.strcpy,valist.CopyToSelf,valist.Uninitialized,valist.Unterminated,core.CallAndMessage,core.DivideZero,core.NonNullParamChecker,core.NullDereference,core.StackAddressEscape,core.UndefinedBinaryOperatorResult,core.VLASize,core.uninitialized.ArraySubscript,core.uninitialized.Assign,core.uninitialized.Branch,core.uninitialized.CapturedBlockVariable,core.uninitialized.UndefReturn,cplusplus.InnerPointer,cplusplus.Move,cplusplus.NewDelete,cplusplus.NewDeleteLeaks,cplusplus.PlacementNew,cplusplus.PureVirtualCall,deadcode.DeadStores,nullability.NullPassedToNonnull,nullability.NullReturnedFromNonnull,security.insecureAPI.UncheckedReturn,security.insecureAPI.decodeValueOfObjCType,security.insecureAPI.getpw,security.insecureAPI.gets,security.insecureAPI.mkstemp,security.insecureAPI.mktemp,security.insecureAPI.vfork,unix.API,unix.Malloc,unix.MallocSizeof,unix.MismatchedDeallocator,unix.Vfork,unix.cstring.BadSizeArg,unix.cstring.NullArg")

add_custom_target(ci_clang_analyze
    COMMAND CXX=${CLANG_TOOL} ${CMAKE_COMMAND}
        -DCMAKE_BUILD_TYPE=Debug -GNinja
        -DJSON_BuildTests=ON
        -S${PROJECT_SOURCE_DIR} -B${PROJECT_BINARY_DIR}/build_clang_analyze
    COMMAND cd ${PROJECT_BINARY_DIR}/build_clang_analyze && ${SCAN_BUILD_TOOL} -enable-checker ${CLANG_ANALYZER_CHECKS} --use-c++=${CLANG_TOOL} --use-analyzer=${CLANG_TOOL} -analyze-headers --status-bugs -o ${PROJECT_BINARY_DIR}/report ninja
    COMMENT "Check code with Clang Analyzer"
)

###############################################################################
# Check code with Cppcheck.
###############################################################################

add_custom_target(ci_cppcheck
    COMMAND mkdir -p cppcheck
    COMMAND clang -dM -E -x c++ -std=c++11 ${CMAKE_SOURCE_DIR}/include/nlohmann/thirdparty/hedley/hedley.hpp > default_defines.hpp 2> /dev/null
    COMMAND ${Python3_EXECUTABLE} -mvenv venv_cppcheck
    COMMAND venv_cppcheck/bin/pip3 --quiet install -r ${CMAKE_SOURCE_DIR}/cmake/requirements/requirements-cppcheck.txt
    COMMAND venv_cppcheck/bin/cppcheck --enable=warning --check-level=exhaustive --inline-suppr --inconclusive --force
            --std=c++11 ${PROJECT_SOURCE_DIR}/include/nlohmann/json.hpp -I ${CMAKE_SOURCE_DIR}/include
            --error-exitcode=1 --relative-paths=${PROJECT_SOURCE_DIR} -j ${N} --include=default_defines.hpp
            --cppcheck-build-dir=cppcheck
            -UJSON_CATCH_USER -UJSON_TRY_USER -UJSON_ASSERT -UJSON_INTERNAL_CATCH -UJSON_THROW
            -DJSON_HAS_CPP_11 -UJSON_HAS_CPP_14 -UJSON_HAS_CPP_17 -UJSON_HAS_CPP_20 -UJSON_HAS_THREE_WAY_COMPARISON
    COMMENT "Check code with Cppcheck"
)

###############################################################################
# Check code with cpplint.
###############################################################################

add_custom_target(ci_cpplint
    COMMAND ${Python3_EXECUTABLE} -mvenv venv_cpplint
    COMMAND venv_cpplint/bin/pip3 --quiet install -r ${CMAKE_SOURCE_DIR}/cmake/requirements/requirements-cpplint.txt
    COMMAND venv_cpplint/bin/cpplint --filter=-whitespace,-legal,-runtime/references,-runtime/explicit,-runtime/indentation_namespace,-readability/casting,-readability/nolint --quiet --recursive ${SRC_FILES}
    COMMENT "Check code with cpplint"
    WORKING_DIRECTORY ${PROJECT_BINARY_DIR}
)

###############################################################################
# Check code with Clang-Tidy.
###############################################################################

add_custom_target(ci_clang_tidy
    COMMAND CXX=${CLANG_TOOL} ${CMAKE_COMMAND}
        -DCMAKE_BUILD_TYPE=Debug -GNinja
        -DCMAKE_EXPORT_COMPILE_COMMANDS=ON -DCMAKE_CXX_CLANG_TIDY=${CLANG_TIDY_TOOL}
        -DJSON_BuildTests=ON
        -S${PROJECT_SOURCE_DIR} -B${PROJECT_BINARY_DIR}/build_clang_tidy
    COMMAND ${CMAKE_COMMAND} --build ${PROJECT_BINARY_DIR}/build_clang_tidy
    COMMENT "Check code with Clang-Tidy"
)

###############################################################################
# Check code with Infer <https://fbinfer.com> static analyzer.
###############################################################################

# .inferconfig (repository root) pins --fail-on-issue and the currently-triaged issue types that
# are disabled until they are addressed separately; see #5715 item 4b.
add_custom_target(ci_infer
    COMMAND mkdir -p ${PROJECT_BINARY_DIR}/build_infer
    COMMAND cd ${PROJECT_BINARY_DIR}/build_infer && ${INFER_TOOL} compile -- ${CMAKE_COMMAND} -DCMAKE_BUILD_TYPE=Debug ${PROJECT_SOURCE_DIR} -DJSON_BuildTests=ON
    COMMAND cd ${PROJECT_BINARY_DIR}/build_infer && ${INFER_TOOL} run --project-root ${PROJECT_SOURCE_DIR} -- make
    COMMENT "Check code with Infer"
)

###############################################################################
# Run test suite with previously downloaded test data.
###############################################################################

add_custom_target(ci_offline_testdata
    COMMAND mkdir -p ${PROJECT_BINARY_DIR}/build_offline_testdata/test_data
    COMMAND cd ${PROJECT_BINARY_DIR}/build_offline_testdata/test_data && ${GIT_TOOL} clone -c advice.detachedHead=false --branch v3.2.0 https://github.com/nlohmann/json_test_data.git --quiet --depth 1
    COMMAND ${CMAKE_COMMAND}
        -DCMAKE_BUILD_TYPE=Debug -GNinja
        -DJSON_BuildTests=ON -DJSON_FastTests=ON -DJSON_TestDataDirectory=${PROJECT_BINARY_DIR}/build_offline_testdata/test_data/json_test_data
        -S${PROJECT_SOURCE_DIR} -B${PROJECT_BINARY_DIR}/build_offline_testdata
    COMMAND ${CMAKE_COMMAND} --build ${PROJECT_BINARY_DIR}/build_offline_testdata
    COMMAND cd ${PROJECT_BINARY_DIR}/build_offline_testdata && ${CMAKE_CTEST_COMMAND} --parallel ${N} --output-on-failure
    COMMENT "Check code with previously downloaded test data"
)

###############################################################################
# Run test suite when project was not checked out from Git
###############################################################################

add_custom_target(ci_non_git_tests
    COMMAND git config --global --add safe.directory ${PROJECT_SOURCE_DIR}
    COMMAND mkdir -p ${PROJECT_BINARY_DIR}/build_non_git_tests/sources
    COMMAND cd ${PROJECT_SOURCE_DIR} && for FILE in `${GIT_TOOL} ls-tree --name-only HEAD`\; do cp -r $$FILE ${PROJECT_BINARY_DIR}/build_non_git_tests/sources \; done
    COMMAND ${CMAKE_COMMAND}
        -DCMAKE_BUILD_TYPE=Debug -GNinja
        -DJSON_BuildTests=ON -DJSON_FastTests=ON
        -S${PROJECT_BINARY_DIR}/build_non_git_tests/sources -B${PROJECT_BINARY_DIR}/build_non_git_tests
    COMMAND ${CMAKE_COMMAND} --build ${PROJECT_BINARY_DIR}/build_non_git_tests
    COMMAND cd ${PROJECT_BINARY_DIR}/build_non_git_tests && ${CMAKE_CTEST_COMMAND} --parallel ${N} -LE git_required --output-on-failure
    COMMENT "Check code when project was not checked out from Git"
)

###############################################################################
# Run test suite and exclude tests that change installed files
###############################################################################

add_custom_target(ci_reproducible_tests
    COMMAND ${CMAKE_COMMAND}
        -DCMAKE_BUILD_TYPE=Debug -GNinja
        -DJSON_BuildTests=ON -DJSON_FastTests=ON
        -S${PROJECT_SOURCE_DIR} -B${PROJECT_BINARY_DIR}/build_reproducible_tests
    COMMAND ${CMAKE_COMMAND} --build ${PROJECT_BINARY_DIR}/build_reproducible_tests
    COMMAND cd ${PROJECT_BINARY_DIR}/build_reproducible_tests && ${CMAKE_CTEST_COMMAND} --parallel ${N} -LE not_reproducible --output-on-failure
    COMMENT "Check code and exclude tests that change installed files"
)

###############################################################################
# Check if every header in the include folder includes sufficient headers to
# be compiled individually.
###############################################################################

set(iwyu_options -Xiwyu --error -Xiwyu --max_line_length=300)
set(iwyu_path_and_options ${IWYU_TOOL} ${iwyu_options})

# CMake needs to know the exact flags used to compile each src_single/*.cpp below to hand them to
# iwyu_tool.py; JSON_CI already implies a from-scratch configure, so enabling this project-wide has
# no downside here.
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

foreach(SRC_FILE ${SRC_FILES})
    # get relative path of the header file
    file(RELATIVE_PATH RELATIVE_SRC_FILE "${PROJECT_SOURCE_DIR}/include/nlohmann" "${SRC_FILE}")
    # replace slashes and strip suffix
    string(REPLACE "/" "_" RELATIVE_SRC_FILE "${RELATIVE_SRC_FILE}")
    string(REPLACE ".hpp" "" RELATIVE_SRC_FILE "${RELATIVE_SRC_FILE}")
    # create code file
    file(WRITE "${PROJECT_BINARY_DIR}/src_single/${RELATIVE_SRC_FILE}.cpp" "#include \"${SRC_FILE}\" // IWYU pragma: keep\n\nint main()\n{}\n")
    # create executable
    add_executable(single_${RELATIVE_SRC_FILE} EXCLUDE_FROM_ALL ${PROJECT_BINARY_DIR}/src_single/${RELATIVE_SRC_FILE}.cpp)
    target_include_directories(single_${RELATIVE_SRC_FILE} PRIVATE ${PROJECT_SOURCE_DIR}/include)
    target_compile_features(single_${RELATIVE_SRC_FILE} PRIVATE cxx_std_11)
    if(RELATIVE_SRC_FILE STREQUAL "json" OR RELATIVE_SRC_FILE STREQUAL "json_literals")
        # see below: report the diagnostics of json.hpp and json_literals.hpp without --error, so they
        # do not fail the build
        set_property(TARGET single_${RELATIVE_SRC_FILE} PROPERTY CXX_INCLUDE_WHAT_YOU_USE ${IWYU_TOOL} -Xiwyu --max_line_length=300)
    else()
        set_property(TARGET single_${RELATIVE_SRC_FILE} PROPERTY CXX_INCLUDE_WHAT_YOU_USE "${iwyu_path_and_options}")
    endif()
    # remember binary for ci_single_binaries
    list(APPEND single_binaries single_${RELATIVE_SRC_FILE})
    # json.hpp pulls together the whole library behind heavily templated, SFINAE-based code, and
    # IWYU's suggestion for its one truly ambiguous symbol (a container-comparison "swap,
    # operator!=") is not deterministic between runs (observed <set>, <unordered_map>, and <map>
    # for the exact same source across otherwise-identical local and containerized builds). Keep
    # reporting its diagnostics (informational, via CXX_INCLUDE_WHAT_YOU_USE above) but exclude it
    # from the hard gate below so a fresh IWYU/compiler combination does not fail this target on a
    # nondeterministic suggestion for a header that already re-exports everything on purpose.
    # json_literals.hpp and json.hpp include each other on purpose (json.hpp includes it at its end
    # unless JSON_NO_AUTOMATIC_UDLS is defined), and IWYU, not following the cycle, suggests replacing
    # json.hpp with json_fwd.hpp although the literals need the complete basic_json; exclude it, too.
    if(NOT RELATIVE_SRC_FILE STREQUAL "json" AND NOT RELATIVE_SRC_FILE STREQUAL "json_literals")
        list(APPEND single_binaries_tus src_single/${RELATIVE_SRC_FILE}.cpp)
    endif()
endforeach()

if(IWYU_TOOL_PY)
    add_custom_target(ci_single_binaries
        DEPENDS ${single_binaries}
        COMMAND ${IWYU_TOOL_PY} -p ${PROJECT_BINARY_DIR} ${single_binaries_tus} -- ${iwyu_options}
        COMMENT "Check if headers are self-contained"
    )
else()
    # iwyu_tool.py (ships with IWYU, e.g. as /usr/bin/iwyu_tool on Debian/Ubuntu) was not found;
    # fall back to building the self-containment check without enforcing the IWYU findings.
    add_custom_target(ci_single_binaries
        DEPENDS ${single_binaries}
        COMMENT "Check if headers are self-contained"
    )
endif()

###############################################################################
# Benchmarks
###############################################################################

add_custom_target(ci_benchmarks
    COMMAND ${CMAKE_COMMAND}
        -DCMAKE_BUILD_TYPE=Release -GNinja
        -S${PROJECT_SOURCE_DIR}/tests/benchmarks -B${PROJECT_BINARY_DIR}/build_benchmarks
    COMMAND ${CMAKE_COMMAND} --build ${PROJECT_BINARY_DIR}/build_benchmarks --target json_benchmarks
    COMMAND cd ${PROJECT_BINARY_DIR}/build_benchmarks && ./json_benchmarks
    COMMENT "Run benchmarks"
)

###############################################################################
# CMake flags
###############################################################################

# we test the project with different CMake versions:
# - CMake 3.5 (the earliest supported)
# - CMake 3.31.6 (the latest 3.x release)
# - CMake 4.0.0 (the first 4.x release)
# - the CMake version running this build (usually the latest release)

function(ci_get_cmake version var)
    set(${var} ${PROJECT_BINARY_DIR}/cmake-${version}/bin/cmake)
    if(CMAKE_HOST_SYSTEM_NAME STREQUAL "Linux" AND CMAKE_HOST_SYSTEM_PROCESSOR MATCHES "^(x86_64|amd64)$")
        # Kitware publishes a prebuilt Linux x86_64 archive for every release; unpacking it is far
        # cheaper than compiling all of CMake (including its own test helpers) from source.
        add_custom_command(
            OUTPUT ${${var}}
            COMMAND wget -nc https://github.com/Kitware/CMake/releases/download/v${version}/cmake-${version}-linux-x86_64.tar.gz
            COMMAND wget -nc https://github.com/Kitware/CMake/releases/download/v${version}/cmake-${version}-SHA-256.txt
            # verify the archive against Kitware's published SHA-256 sums before unpacking it; old
            # releases list the archive as "Linux-x86_64", so match case-insensitively and rewrite
            # the name to the lowercase one the download was saved under
            COMMAND sh -c "grep -i ' cmake-${version}-linux-x86_64[.]tar[.]gz$' cmake-${version}-SHA-256.txt | tr L l | sha256sum -c -"
            # unpack into cmake-${version} directly, as the archive's top-level directory is spelled
            # "Linux" in old releases and "linux" in newer ones
            COMMAND ${CMAKE_COMMAND} -E rm -rf cmake-${version}
            COMMAND ${CMAKE_COMMAND} -E make_directory cmake-${version}
            COMMAND tar xfz cmake-${version}-linux-x86_64.tar.gz -C cmake-${version} --strip-components=1
            COMMAND rm cmake-${version}-linux-x86_64.tar.gz cmake-${version}-SHA-256.txt
            WORKING_DIRECTORY ${PROJECT_BINARY_DIR}
            COMMENT "Download prebuilt CMake ${version}"
            VERBATIM
        )
    else()
        # no prebuilt archive for this platform (e.g. macOS or Linux aarch64): build from source
        add_custom_command(
            OUTPUT ${${var}}
            COMMAND wget -nc https://github.com/Kitware/CMake/releases/download/v${version}/cmake-${version}.tar.gz
            COMMAND tar xfz cmake-${version}.tar.gz
            COMMAND rm cmake-${version}.tar.gz
            # -DCMAKE_POLICY_VERSION_MINIMUM=3.5 required to compile older CMake versions with CMake 4.0.0
            COMMAND cmake -S cmake-${version} -B cmake-${version} -DCMAKE_POLICY_VERSION_MINIMUM=3.5
            COMMAND cmake --build cmake-${version} --parallel 10
            WORKING_DIRECTORY ${PROJECT_BINARY_DIR}
            COMMENT "Download and build CMake ${version} from source"
        )
    endif()
    set(${var} ${${var}} PARENT_SCOPE)
endfunction()

ci_get_cmake(3.5.0  CMAKE_3_5_0_BINARY)
ci_get_cmake(3.31.6 CMAKE_3_31_6_BINARY)
ci_get_cmake(4.0.0  CMAKE_4_0_0_BINARY)

# the tests require CMake 3.13 or later, so they are excluded for CMake 3.5.0
set(JSON_CMAKE_FLAGS_3_5_0 JSON_Diagnostics JSON_Diagnostic_Positions JSON_GlobalUDLs JSON_ImplicitConversions JSON_DisableEnumSerialization
    JSON_LegacyDiscardedValueComparison JSON_Install JSON_MultipleHeaders JSON_SystemInclude JSON_Valgrind
    JSON_StrictNulHandling JSON_StrictBinaryUTF8)
set(JSON_CMAKE_FLAGS_3_31_6 JSON_BuildTests ${JSON_CMAKE_FLAGS_3_5_0})
set(JSON_CMAKE_FLAGS_4_0_0 JSON_BuildTests ${JSON_CMAKE_FLAGS_3_5_0})

function(ci_add_cmake_flags_targets flag min_version)
    string(TOLOWER "ci_cmake_flag_${flag}" flag_target)
    string(REPLACE . _ min_version_var ${min_version})
    set(cmake_binary ${CMAKE_${min_version_var}_BINARY})
    add_custom_target(${flag_target}_${min_version_var}
        COMMENT "Check CMake flag ${flag} (CMake ${min_version})"
        COMMAND mkdir -pv ${PROJECT_BINARY_DIR}/build_${flag_target}_${min_version_var}
        COMMAND cd ${PROJECT_BINARY_DIR}/build_${flag_target}_${min_version_var}
            && ${cmake_binary} -Werror=dev ${PROJECT_SOURCE_DIR} -D${flag}=ON
        DEPENDS ${cmake_binary}
    )
    list(APPEND JSON_CMAKE_FLAG_TARGETS ${flag_target}_${min_version_var})
    list(APPEND JSON_CMAKE_FLAG_BUILD_DIRS ${PROJECT_BINARY_DIR}/build_${flag_target}_${min_version_var})
    set(JSON_CMAKE_FLAG_TARGETS ${JSON_CMAKE_FLAG_TARGETS} PARENT_SCOPE)
    set(JSON_CMAKE_FLAG_BUILD_DIRS ${JSON_CMAKE_FLAG_BUILD_DIRS} PARENT_SCOPE)
endfunction()

foreach(JSON_CMAKE_FLAG ${JSON_CMAKE_FLAGS_3_5_0})
    ci_add_cmake_flags_targets(${JSON_CMAKE_FLAG} 3.5.0)
endforeach()

foreach(JSON_CMAKE_FLAG ${JSON_CMAKE_FLAGS_3_31_6})
    ci_add_cmake_flags_targets(${JSON_CMAKE_FLAG} 3.31.6)
endforeach()

foreach(JSON_CMAKE_FLAG ${JSON_CMAKE_FLAGS_4_0_0})
    ci_add_cmake_flags_targets(${JSON_CMAKE_FLAG} 4.0.0)
endforeach()

# check the same flags with the CMake version running this build
foreach(JSON_CMAKE_FLAG ${JSON_CMAKE_FLAGS_4_0_0})
    string(TOLOWER "ci_cmake_flag_${JSON_CMAKE_FLAG}" flag_target)
    add_custom_target(${flag_target}
        COMMENT "Check CMake flag ${JSON_CMAKE_FLAG} (CMake ${CMAKE_VERSION})"
        COMMAND ${CMAKE_COMMAND}
            -Werror=dev
            -D${JSON_CMAKE_FLAG}=ON
            -S${PROJECT_SOURCE_DIR} -B${PROJECT_BINARY_DIR}/build_${flag_target}
    )
    list(APPEND JSON_CMAKE_FLAG_TARGETS ${flag_target})
    list(APPEND JSON_CMAKE_FLAG_BUILD_DIRS ${PROJECT_BINARY_DIR}/build_${flag_target})
endforeach()

add_custom_target(ci_cmake_flags
    DEPENDS ${JSON_CMAKE_FLAG_TARGETS}
    COMMENT "Check CMake flags"
)

###############################################################################
# Use more installed compilers.
###############################################################################

foreach(COMPILER g++-4.8 g++-4.9 g++-5 g++-6 g++-7 g++-8 g++-9 g++-10 g++-11 clang++-3.5 clang++-3.6 clang++-3.7 clang++-3.8 clang++-3.9 clang++-4.0 clang++-5.0 clang++-6.0 clang++-7 clang++-8 clang++-9 clang++-10 clang++-11 clang++-12 clang++-13 clang++-14 clang++-15 clang++-16 clang++-17 clang++-18 clang++-19 clang++-20)
    find_program(COMPILER_TOOL NAMES ${COMPILER})
    if (COMPILER_TOOL)
        unset(ADDITIONAL_FLAGS)

        add_custom_target(ci_test_compiler_${COMPILER}
            COMMAND CXX=${COMPILER} ${CMAKE_COMMAND}
                -DCMAKE_BUILD_TYPE=Debug -GNinja
                -DJSON_BuildTests=ON -DJSON_FastTests=ON
                -S${PROJECT_SOURCE_DIR} -B${PROJECT_BINARY_DIR}/build_compiler_${COMPILER}
                ${ADDITIONAL_FLAGS}
            COMMAND ${CMAKE_COMMAND} --build ${PROJECT_BINARY_DIR}/build_compiler_${COMPILER}
            COMMAND cd ${PROJECT_BINARY_DIR}/build_compiler_${COMPILER} && ${CMAKE_CTEST_COMMAND} --parallel ${N} --exclude-regex "test-unicode" --output-on-failure
            COMMENT "Compile and test with ${COMPILER}"
        )
    endif()
    unset(COMPILER_TOOL CACHE)
endforeach()

add_custom_target(ci_test_compiler_default
    COMMAND ${CMAKE_COMMAND}
        -DCMAKE_BUILD_TYPE=Debug -GNinja
        -DJSON_BuildTests=ON -DJSON_FastTests=ON
        -S${PROJECT_SOURCE_DIR} -B${PROJECT_BINARY_DIR}/build_compiler_default
        ${ADDITIONAL_FLAGS}
    COMMAND ${CMAKE_COMMAND} --build ${PROJECT_BINARY_DIR}/build_compiler_default --parallel ${N}
    COMMAND cd ${PROJECT_BINARY_DIR}/build_compiler_default && ${CMAKE_CTEST_COMMAND} --parallel ${N} --exclude-regex "test-unicode" -LE git_required --output-on-failure
    COMMENT "Compile and test with default C++ compiler"
)

###############################################################################
# CUDA example
###############################################################################

add_custom_target(ci_cuda_example
    COMMAND ${CMAKE_COMMAND}
        -DCMAKE_BUILD_TYPE=Debug -GNinja
        -S${PROJECT_SOURCE_DIR}/tests/cuda_example -B${PROJECT_BINARY_DIR}/build_cuda_example
    COMMAND ${CMAKE_COMMAND} --build ${PROJECT_BINARY_DIR}/build_cuda_example
)

###############################################################################
# C++ 20 modules
###############################################################################

add_custom_target(ci_module_cpp20
    COMMAND ${CMAKE_COMMAND}
        -DCMAKE_BUILD_TYPE=Debug -GNinja 
        -DJSON_CI=ON -DNLOHMANN_JSON_BUILD_MODULES=ON -DJSON_Install=ON
        -S${PROJECT_SOURCE_DIR}/tests/module_cpp20 -B${PROJECT_BINARY_DIR}/ci_module_cpp20
    COMMAND ${CMAKE_COMMAND} --build ${PROJECT_BINARY_DIR}/ci_module_cpp20
)

###############################################################################
# Intel C++ Compiler
###############################################################################

add_custom_target(ci_icpc
    COMMAND ${CMAKE_COMMAND}
        -DCMAKE_BUILD_TYPE=Debug -GNinja
        -DCMAKE_C_COMPILER=icc -DCMAKE_CXX_COMPILER=icpc
        -DJSON_BuildTests=ON -DJSON_FastTests=ON
        -S${PROJECT_SOURCE_DIR} -B${PROJECT_BINARY_DIR}/build_icpc
    COMMAND ${CMAKE_COMMAND} --build ${PROJECT_BINARY_DIR}/build_icpc
    COMMAND cd ${PROJECT_BINARY_DIR}/build_icpc && ${CMAKE_CTEST_COMMAND} --parallel ${N} --exclude-regex "test-unicode" --output-on-failure
    COMMENT "Compile and test with ICPC"
)

add_custom_target(ci_icpx
    COMMAND ${CMAKE_COMMAND}
        -DCMAKE_BUILD_TYPE=Debug -GNinja
        -DCMAKE_C_COMPILER=icx -DCMAKE_CXX_COMPILER=icpx
        -DJSON_BuildTests=ON -DJSON_FastTests=ON
        -S${PROJECT_SOURCE_DIR} -B${PROJECT_BINARY_DIR}/build_icpx
    COMMAND ${CMAKE_COMMAND} --build ${PROJECT_BINARY_DIR}/build_icpx
    COMMAND cd ${PROJECT_BINARY_DIR}/build_icpx && ${CMAKE_CTEST_COMMAND} --parallel ${N} --exclude-regex "test-unicode" --output-on-failure
    COMMENT "Compile and test with ICPX (Intel oneAPI DPC++/C++)"
)

###############################################################################
# NVIDIA HPC SDK C++ Compiler
###############################################################################

# nvc++ defaults to a relaxed, non-IEEE floating-point model that flushes denormals
# to zero and does not honor NaN ordering; -Kieee restores strict IEEE 754 behavior
# (needed for the dtoa/grisu and NaN-comparison code paths).
#
# -tp=px pins the target processor to the generic x86-64 baseline (SSE2-only) to avoid
# a nvc++ 25.5 / LLVM issue: when nvc++ auto-detects -tp from the runner's CPU (e.g. -tp znver4),
# certain attribute combinations trigger an llc instruction-selection crash on std::ldexp<unsigned>.
# Pinning to px removes this variability and is robust to future llc/nvc++ updates.
#
# The following tests are excluded as they trigger known nvc++ 25.5 defects (not
# library bugs); see https://github.com/nlohmann/json for tracking. Only the
# affected language-standard variants are excluded so coverage is otherwise kept:
#   - test-comparison_cpp20, test-comparison_legacy_cpp20
#         miscompiles cross-type/<=> comparison (e.g. `-17 <= null`)
#   - test-constructor1_cpp11
#         std::initializer_list lifetime bug -> SIGSEGV
#   - test-deserialization_cpp20
#         mangles the UTF-8 u8"" string literal in the char8_t (C++20) section
add_custom_target(ci_nvhpc
    COMMAND ${CMAKE_COMMAND}
        -DCMAKE_BUILD_TYPE=Debug -GNinja
        -DCMAKE_C_COMPILER=nvc -DCMAKE_CXX_COMPILER=nvc++
        -DCMAKE_CXX_FLAGS="-Kieee;-tp=px"
        -DJSON_BuildTests=ON -DJSON_FastTests=ON
        -S${PROJECT_SOURCE_DIR} -B${PROJECT_BINARY_DIR}/build_nvhpc
    COMMAND ${CMAKE_COMMAND} --build ${PROJECT_BINARY_DIR}/build_nvhpc
    # the pipes are escaped so the surrounding shell passes them to ctest verbatim
    # instead of treating them as shell pipe operators
    COMMAND cd ${PROJECT_BINARY_DIR}/build_nvhpc && ${CMAKE_CTEST_COMMAND} --parallel ${N} --exclude-regex "test-unicode\\|test-comparison_cpp20\\|test-comparison_legacy_cpp20\\|test-constructor1_cpp11\\|test-deserialization_cpp20" --output-on-failure
    COMMENT "Compile and test with NVIDIA HPC SDK (nvc++)"
)

###############################################################################
# REUSE
###############################################################################

add_custom_target(ci_reuse_compliance
    COMMAND ${Python3_EXECUTABLE} -mvenv venv_reuse
    COMMAND venv_reuse/bin/pip3 --quiet install -r ${PROJECT_SOURCE_DIR}/cmake/requirements/requirements-reuse.txt
    COMMAND venv_reuse/bin/reuse --root ${PROJECT_SOURCE_DIR} lint
    COMMENT "Check REUSE specification compliance"
)

###############################################################################
# test documentation
###############################################################################

add_custom_target(ci_test_examples
    COMMAND make CXX="${GCC_TOOL}" check_output_portable -j8
    WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}/docs
    COMMENT "Check that all examples compile and create the desired output"
)

add_custom_target(ci_test_build_documentation
    COMMAND ${Python3_EXECUTABLE} -mvenv venv
    COMMAND venv/bin/pip3 --quiet install -r requirements.txt
    COMMAND make build
    WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}/docs/mkdocs
    COMMENT "Build the documentation"
)

add_custom_target(ci_test_documentation_mermaid
    COMMAND make check_mermaid
    WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}/docs/mkdocs
    COMMENT "Check the Mermaid diagrams of the documentation"
)

###############################################################################
# Clean up all generated files.
###############################################################################

add_custom_target(ci_clean
    COMMAND rm -fr ${PROJECT_BINARY_DIR}/build_* ${PROJECT_BINARY_DIR}/cmake-3.5.0 ${PROJECT_BINARY_DIR}/cmake-3.31.6 ${PROJECT_BINARY_DIR}/cmake-4.0.0 ${JSON_CMAKE_FLAG_BUILD_DIRS} ${single_binaries}
    COMMENT "Clean generated directories"
)
