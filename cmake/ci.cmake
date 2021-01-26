# macOS

# brew install llvm cppcheck iwyu infer oclint/formulae/oclint
# brew install viva64/pvs-studio/pvs-studio
#   (you will need credentials)
# brew install gcc --HEAD

###############################################################################
# Needed tools.
###############################################################################

include(FindPython3)
find_package(Python3 COMPONENTS Interpreter)

message(STATUS "🔖 CMake ${CMAKE_VERSION} (${CMAKE_COMMAND})")

find_program(CLANG_TIDY_TOOL NAMES clang-tidy-11 clang-tidy)
execute_process(COMMAND ${CLANG_TIDY_TOOL} --version OUTPUT_VARIABLE CLANG_TIDY_TOOL_VERSION ERROR_VARIABLE CLANG_TIDY_TOOL_VERSION)
string(REGEX MATCH "[0-9]+(\\.[0-9]+)+" CLANG_TIDY_TOOL_VERSION "${CLANG_TIDY_TOOL_VERSION}")
message(STATUS "🔖 Clang-Tidy ${CLANG_TIDY_TOOL_VERSION} (${CLANG_TIDY_TOOL})")

find_program(CLANG_TOOL NAMES clang++-HEAD clang++-11 clang++)
execute_process(COMMAND ${CLANG_TOOL} --version OUTPUT_VARIABLE CLANG_TOOL_VERSION ERROR_VARIABLE CLANG_TOOL_VERSION)
string(REGEX MATCH "[0-9]+(\\.[0-9]+)+" CLANG_TOOL_VERSION "${CLANG_TOOL_VERSION}")
message(STATUS "🔖 Clang ${CLANG_TOOL_VERSION} (${CLANG_TOOL})")

find_program(CPPCHECK_TOOL NAMES cppcheck)
execute_process(COMMAND ${CPPCHECK_TOOL} --version OUTPUT_VARIABLE CPPCHECK_TOOL_VERSION ERROR_VARIABLE CPPCHECK_TOOL_VERSION)
string(REGEX MATCH "[0-9]+(\\.[0-9]+)+" CPPCHECK_TOOL_VERSION "${CPPCHECK_TOOL_VERSION}")
message(STATUS "🔖 Cppcheck ${CPPCHECK_TOOL_VERSION} (${CPPCHECK_TOOL})")

find_program(GCC_TOOL NAMES g++-HEAD g++-11 g++-10 g++)
execute_process(COMMAND ${GCC_TOOL} --version OUTPUT_VARIABLE GCC_TOOL_VERSION ERROR_VARIABLE GCC_TOOL_VERSION)
string(REGEX MATCH "[0-9]+(\\.[0-9]+)+" GCC_TOOL_VERSION "${GCC_TOOL_VERSION}")
message(STATUS "🔖 GCC ${GCC_TOOL_VERSION} (${GCC_TOOL})")

find_program(INFER_TOOL NAMES infer)
execute_process(COMMAND ${INFER_TOOL} --version OUTPUT_VARIABLE INFER_TOOL_VERSION ERROR_VARIABLE INFER_TOOL_VERSION)
string(REGEX MATCH "[0-9]+(\\.[0-9]+)+" INFER_TOOL_VERSION "${INFER_TOOL_VERSION}")
message(STATUS "🔖 Infer ${INFER_TOOL_VERSION} (${INFER_TOOL})")

find_program(IWYU_TOOL NAMES include-what-you-use iwyu)
execute_process(COMMAND ${IWYU_TOOL} --version OUTPUT_VARIABLE IWYU_TOOL_VERSION ERROR_VARIABLE IWYU_TOOL_VERSION)
string(REGEX MATCH "[0-9]+(\\.[0-9]+)+" IWYU_TOOL_VERSION "${IWYU_TOOL_VERSION}")
message(STATUS "🔖 include-what-you-use ${IWYU_TOOL_VERSION} (${IWYU_TOOL})")

find_program(VALGRIND_TOOL NAMES valgrind)
execute_process(COMMAND ${VALGRIND_TOOL} --version OUTPUT_VARIABLE VALGRIND_TOOL_VERSION ERROR_VARIABLE VALGRIND_TOOL_VERSION)
string(REGEX MATCH "[0-9]+(\\.[0-9]+)+" VALGRIND_TOOL_VERSION "${VALGRIND_TOOL_VERSION}")
message(STATUS "🔖 Valgrind ${VALGRIND_TOOL_VERSION} (${VALGRIND_TOOL})")

find_program(OCLINT_TOOL NAMES oclint-json-compilation-database)
find_program(PLOG_CONVERTER_TOOL NAMES plog-converter)
find_program(PVS_STUDIO_ANALYZER_TOOL NAMES pvs-studio-analyzer)
find_program(SCAN_BUILD_TOOL NAMES scan-build-11 scan-build)

# the individual source files
file(GLOB_RECURSE SRC_FILES ${PROJECT_SOURCE_DIR}/include/nlohmann/*.hpp)

set(CLANG_CXXFLAGS "-std=c++11                        \
    -Werror                                           \
    -Weverything                                      \
    -Wno-c++98-compat                                    \
    -Wno-c++98-compat-pedantic                           \
    -Wno-deprecated-declarations                         \
    -Wno-documentation-unknown-command                   \
    -Wno-exit-time-destructors                           \
    -Wno-extra-semi-stmt                                 \
    -Wno-padded                                          \
    -Wno-range-loop-analysis                             \
    -Wno-switch-enum -Wno-covered-switch-default         \
    -Wno-weak-vtables                                    \
")

set(GCC_CXXFLAGS "-std=c++11                          \
    -pedantic                                         \
    -Werror                                           \
    --all-warnings                                    \
    --extra-warnings                                  \
    -W                                                \
    -WNSObject-attribute                              \
    -Wno-abi-tag                                         \
    -Waddress                                         \
    -Waddress-of-packed-member                        \
    -Wno-aggregate-return                                \
    -Waggressive-loop-optimizations                   \
    -Waligned-new=all                                 \
    -Wall                                             \
    -Walloc-zero                                      \
    -Walloca                                          \
    -Wanalyzer-double-fclose                          \
    -Wanalyzer-double-free                            \
    -Wanalyzer-exposure-through-output-file           \
    -Wanalyzer-file-leak                              \
    -Wanalyzer-free-of-non-heap                       \
    -Wanalyzer-malloc-leak                            \
    -Wanalyzer-mismatching-deallocation               \
    -Wanalyzer-null-argument                          \
    -Wanalyzer-null-dereference                       \
    -Wanalyzer-possible-null-argument                 \
    -Wanalyzer-possible-null-dereference              \
    -Wanalyzer-shift-count-negative                   \
    -Wanalyzer-shift-count-overflow                   \
    -Wanalyzer-stale-setjmp-buffer                    \
    -Wanalyzer-tainted-array-index                    \
    -Wanalyzer-too-complex                            \
    -Wanalyzer-unsafe-call-within-signal-handler      \
    -Wanalyzer-use-after-free                         \
    -Wanalyzer-use-of-pointer-in-stale-stack-frame    \
    -Wanalyzer-write-to-const                         \
    -Wanalyzer-write-to-string-literal                \
    -Warith-conversion                                \
    -Warray-bounds                                    \
    -Warray-bounds=2                                  \
    -Warray-parameter=2                               \
    -Wattribute-alias=2                               \
    -Wattribute-warning                               \
    -Wattributes                                      \
    -Wbool-compare                                    \
    -Wbool-operation                                  \
    -Wbuiltin-declaration-mismatch                    \
    -Wbuiltin-macro-redefined                         \
    -Wc++0x-compat                                    \
    -Wc++11-compat                                    \
    -Wc++14-compat                                    \
    -Wc++17-compat                                    \
    -Wc++1z-compat                                    \
    -Wc++20-compat                                    \
    -Wc++2a-compat                                    \
    -Wcannot-profile                                  \
    -Wcast-align                                      \
    -Wcast-align=strict                               \
    -Wcast-function-type                              \
    -Wcast-qual                                       \
    -Wcatch-value=3                                   \
    -Wchar-subscripts                                 \
    -Wclass-conversion                                \
    -Wclass-memaccess                                 \
    -Wclobbered                                       \
    -Wcomma-subscript                                 \
    -Wcomment                                         \
    -Wcomments                                        \
    -Wconditionally-supported                         \
    -Wconversion                                      \
    -Wconversion-null                                 \
    -Wcoverage-mismatch                               \
    -Wcpp                                             \
    -Wctad-maybe-unsupported                          \
    -Wctor-dtor-privacy                               \
    -Wdangling-else                                   \
    -Wdate-time                                       \
    -Wdelete-incomplete                               \
    -Wdelete-non-virtual-dtor                         \
    -Wdeprecated                                      \
    -Wdeprecated-copy                                 \
    -Wdeprecated-copy-dtor                            \
    -Wdeprecated-declarations                         \
    -Wdeprecated-enum-enum-conversion                 \
    -Wdeprecated-enum-float-conversion                \
    -Wdisabled-optimization                           \
    -Wdiv-by-zero                                     \
    -Wdouble-promotion                                \
    -Wduplicated-branches                             \
    -Wduplicated-cond                                 \
    -Weffc++                                          \
    -Wempty-body                                      \
    -Wendif-labels                                    \
    -Wenum-compare                                    \
    -Wenum-conversion                                 \
    -Wexpansion-to-defined                            \
    -Wextra                                           \
    -Wextra-semi                                      \
    -Wfloat-conversion                                \
    -Wfloat-equal                                     \
    -Wformat-diag                                     \
    -Wformat-overflow=2                               \
    -Wformat-signedness                               \
    -Wformat-truncation=2                             \
    -Wformat=2                                        \
    -Wframe-address                                   \
    -Wfree-nonheap-object                             \
    -Whsa                                             \
    -Wif-not-aligned                                  \
    -Wignored-attributes                              \
    -Wignored-qualifiers                              \
    -Wimplicit-fallthrough=5                          \
    -Winaccessible-base                               \
    -Winherited-variadic-ctor                         \
    -Winit-list-lifetime                              \
    -Winit-self                                       \
    -Winline                                          \
    -Wint-in-bool-context                             \
    -Wint-to-pointer-cast                             \
    -Winvalid-memory-model                            \
    -Winvalid-offsetof                                \
    -Winvalid-pch                                     \
    -Wliteral-suffix                                  \
    -Wlogical-not-parentheses                         \
    -Wlogical-op                                      \
    -Wno-long-long                                       \
    -Wlto-type-mismatch                               \
    -Wmain                                            \
    -Wmaybe-uninitialized                             \
    -Wmemset-elt-size                                 \
    -Wmemset-transposed-args                          \
    -Wmisleading-indentation                          \
    -Wmismatched-dealloc                              \
    -Wmismatched-new-delete                           \
    -Wmismatched-tags                                 \
    -Wmissing-attributes                              \
    -Wmissing-braces                                  \
    -Wmissing-declarations                            \
    -Wmissing-field-initializers                      \
    -Wmissing-include-dirs                            \
    -Wmissing-profile                                 \
    -Wmultichar                                       \
    -Wmultiple-inheritance                            \
    -Wmultistatement-macros                           \
    -Wno-namespaces                                      \
    -Wnarrowing                                       \
    -Wno-noexcept                                        \
    -Wnoexcept-type                                   \
    -Wnon-template-friend                             \
    -Wnon-virtual-dtor                                \
    -Wnonnull                                         \
    -Wnonnull-compare                                 \
    -Wnormalized=nfkc                                 \
    -Wnull-dereference                                \
    -Wodr                                             \
    -Wold-style-cast                                  \
    -Wopenmp-simd                                     \
    -Woverflow                                        \
    -Woverlength-strings                              \
    -Woverloaded-virtual                              \
    -Wpacked                                          \
    -Wpacked-bitfield-compat                          \
    -Wpacked-not-aligned                              \
    -Wno-padded                                          \
    -Wparentheses                                     \
    -Wpedantic                                        \
    -Wpessimizing-move                                \
    -Wplacement-new=2                                 \
    -Wpmf-conversions                                 \
    -Wpointer-arith                                   \
    -Wpointer-compare                                 \
    -Wpragmas                                         \
    -Wprio-ctor-dtor                                  \
    -Wpsabi                                           \
    -Wno-range-loop-construct                            \
    -Wredundant-decls                                 \
    -Wredundant-move                                  \
    -Wredundant-tags                                  \
    -Wregister                                        \
    -Wreorder                                         \
    -Wrestrict                                        \
    -Wreturn-local-addr                               \
    -Wreturn-type                                     \
    -Wscalar-storage-order                            \
    -Wsequence-point                                  \
    -Wshadow=compatible-local                         \
    -Wshadow=global                                   \
    -Wshadow=local                                    \
    -Wshift-count-negative                            \
    -Wshift-count-overflow                            \
    -Wshift-negative-value                            \
    -Wshift-overflow=2                                \
    -Wsign-compare                                    \
    -Wsign-conversion                                 \
    -Wsign-promo                                      \
    -Wsized-deallocation                              \
    -Wsizeof-array-argument                           \
    -Wsizeof-array-div                                \
    -Wsizeof-pointer-div                              \
    -Wsizeof-pointer-memaccess                        \
    -Wstack-protector                                 \
    -Wstrict-aliasing                                 \
    -Wstrict-aliasing=3                               \
    -Wstrict-null-sentinel                            \
    -Wstrict-overflow                                 \
    -Wstrict-overflow=5                               \
    -Wstring-compare                                  \
    -Wstringop-overflow=4                             \
    -Wstringop-overread                               \
    -Wstringop-truncation                             \
    -Wsubobject-linkage                               \
    -Wsuggest-attribute=cold                          \
    -Wsuggest-attribute=const                         \
    -Wsuggest-attribute=format                        \
    -Wsuggest-attribute=malloc                        \
    -Wsuggest-attribute=noreturn                      \
    -Wsuggest-attribute=pure                          \
    -Wsuggest-final-methods                           \
    -Wsuggest-final-types                             \
    -Wsuggest-override                                \
    -Wswitch                                          \
    -Wswitch-bool                                     \
    -Wswitch-default                                  \
    -Wno-switch-enum                                     \
    -Wswitch-outside-range                            \
    -Wswitch-unreachable                              \
    -Wsync-nand                                       \
    -Wsynth                                           \
    -Wno-system-headers                                  \
    -Wtautological-compare                            \
    -Wno-templates                                       \
    -Wterminate                                       \
    -Wtrampolines                                     \
    -Wtrigraphs                                       \
    -Wtsan                                            \
    -Wtype-limits                                     \
    -Wundef                                           \
    -Wuninitialized                                   \
    -Wunknown-pragmas                                 \
    -Wunreachable-code                                \
    -Wunsafe-loop-optimizations                       \
    -Wunused                                          \
    -Wunused-but-set-parameter                        \
    -Wunused-but-set-variable                         \
    -Wunused-const-variable=2                         \
    -Wunused-function                                 \
    -Wunused-label                                    \
    -Wunused-local-typedefs                           \
    -Wunused-macros                                   \
    -Wunused-parameter                                \
    -Wunused-result                                   \
    -Wunused-value                                    \
    -Wunused-variable                                 \
    -Wno-useless-cast                                    \
    -Wvarargs                                         \
    -Wvariadic-macros                                 \
    -Wvector-operation-performance                    \
    -Wvexing-parse                                    \
    -Wvirtual-inheritance                             \
    -Wvirtual-move-assign                             \
    -Wvla                                             \
    -Wvla-parameter                                   \
    -Wvolatile                                        \
    -Wvolatile-register-var                           \
    -Wwrite-strings                                   \
    -Wzero-as-null-pointer-constant                   \
    -Wzero-length-bounds                              \
")

add_custom_target(ci_test_gcc
    COMMAND CXX=${GCC_TOOL} CXXFLAGS=${GCC_CXXFLAGS} ${CMAKE_COMMAND} -DCMAKE_BUILD_TYPE=Debug -S${PROJECT_SOURCE_DIR} -B${PROJECT_BINARY_DIR}/build_gcc -DJSON_BuildTests=ON -GNinja
    COMMAND ${CMAKE_COMMAND} --build ${PROJECT_BINARY_DIR}/build_gcc
    COMMAND cd ${PROJECT_BINARY_DIR}/build_gcc && ${CMAKE_CTEST_COMMAND} -j10
    COMMENT "Compile and test with GCC"
)

add_custom_target(ci_test_clang
    COMMAND CXX=${CLANG_TOOL} CXXFLAGS=${CLANG_CXXFLAGS} ${CMAKE_COMMAND} -DCMAKE_BUILD_TYPE=Debug -S${PROJECT_SOURCE_DIR} -B${PROJECT_BINARY_DIR}/build_clang -DJSON_BuildTests=ON -DJSON_MultipleHeaders=ON -GNinja
    COMMAND ${CMAKE_COMMAND} --build ${PROJECT_BINARY_DIR}/build_clang
    COMMAND cd ${PROJECT_BINARY_DIR}/build_clang && ${CMAKE_CTEST_COMMAND} -j10
    COMMENT "Compile and test with Clang"
)

###############################################################################
# Sanitizers.
###############################################################################

set(CLANG_CXX_FLAGS_SANITIZER "-g -O0 -fsanitize=address -fsanitize=undefined -fsanitize=integer -fsanitize=nullability -fno-omit-frame-pointer -fno-sanitize-recover=all -fsanitize-recover=unsigned-integer-overflow")

add_custom_target(ci_test_clang_sanitizer
    COMMAND CXX=${CLANG_TOOL} CXXFLAGS=${CLANG_CXX_FLAGS_SANITIZER} ${CMAKE_COMMAND} -DCMAKE_BUILD_TYPE=Debug -S${PROJECT_SOURCE_DIR} -B${PROJECT_BINARY_DIR}/build_clang_sanitizer -DJSON_BuildTests=ON -GNinja
    COMMAND ${CMAKE_COMMAND} --build ${PROJECT_BINARY_DIR}/build_clang_sanitizer
    COMMAND cd ${PROJECT_BINARY_DIR}/build_clang_sanitizer && ${CMAKE_CTEST_COMMAND} -j10
    COMMENT "Compile and test with sanitizers"
)

###############################################################################
# Valgrind.
###############################################################################

add_custom_target(ci_test_valgrind
    COMMAND CXX=${GCC_TOOL} ${CMAKE_COMMAND} -DCMAKE_BUILD_TYPE=Debug -S${PROJECT_SOURCE_DIR} -B${PROJECT_BINARY_DIR}/build_valgrind -DJSON_BuildTests=ON -GNinja -DMEMORYCHECK_COMMAND=${VALGRIND_TOOL} -DMEMORYCHECK_COMMAND_OPTIONS="--error-exitcode=1 --leak-check=full"
    COMMAND ${CMAKE_COMMAND} --build ${PROJECT_BINARY_DIR}/build_valgrind
    COMMAND ${CMAKE_COMMAND} --build ${PROJECT_BINARY_DIR}/build_valgrind --target download_test_data
    COMMAND cd ${PROJECT_BINARY_DIR}/build_valgrind && ${CMAKE_CTEST_COMMAND} -T memcheck -j10
    COMMENT "Compile and test with Valgrind"
)

###############################################################################
# Check code with Clang Static Analyzer.
###############################################################################

set(CLANG_ANALYZER_CHECKS "fuchsia.HandleChecker,nullability.NullableDereferenced,nullability.NullablePassedToNonnull,nullability.NullableReturnedFromNonnull,optin.cplusplus.UninitializedObject,optin.cplusplus.VirtualCall,optin.mpi.MPI-Checker,optin.osx.OSObjectCStyleCast,optin.osx.cocoa.localizability.EmptyLocalizationContextChecker,optin.osx.cocoa.localizability.NonLocalizedStringChecker,optin.performance.GCDAntipattern,optin.performance.Padding,optin.portability.UnixAPI,security.FloatLoopCounter,security.insecureAPI.DeprecatedOrUnsafeBufferHandling,security.insecureAPI.bcmp,security.insecureAPI.bcopy,security.insecureAPI.bzero,security.insecureAPI.rand,security.insecureAPI.strcpy,valist.CopyToSelf,valist.Uninitialized,valist.Unterminated,webkit.NoUncountedMemberChecker,webkit.RefCntblBaseVirtualDtor,core.CallAndMessage,core.DivideZero,core.NonNullParamChecker,core.NullDereference,core.StackAddressEscape,core.UndefinedBinaryOperatorResult,core.VLASize,core.uninitialized.ArraySubscript,core.uninitialized.Assign,core.uninitialized.Branch,core.uninitialized.CapturedBlockVariable,core.uninitialized.UndefReturn,cplusplus.InnerPointer,cplusplus.Move,cplusplus.NewDelete,cplusplus.NewDeleteLeaks,cplusplus.PlacementNew,cplusplus.PureVirtualCall,deadcode.DeadStores,nullability.NullPassedToNonnull,nullability.NullReturnedFromNonnull,osx.API,osx.MIG,osx.NumberObjectConversion,osx.OSObjectRetainCount,osx.ObjCProperty,osx.SecKeychainAPI,osx.cocoa.AtSync,osx.cocoa.AutoreleaseWrite,osx.cocoa.ClassRelease,osx.cocoa.Dealloc,osx.cocoa.IncompatibleMethodTypes,osx.cocoa.Loops,osx.cocoa.MissingSuperCall,osx.cocoa.NSAutoreleasePool,osx.cocoa.NSError,osx.cocoa.NilArg,osx.cocoa.NonNilReturnValue,osx.cocoa.ObjCGenerics,osx.cocoa.RetainCount,osx.cocoa.RunLoopAutoreleaseLeak,osx.cocoa.SelfInit,osx.cocoa.SuperDealloc,osx.cocoa.UnusedIvars,osx.cocoa.VariadicMethodTypes,osx.coreFoundation.CFError,osx.coreFoundation.CFNumber,osx.coreFoundation.CFRetainRelease,osx.coreFoundation.containers.OutOfBounds,osx.coreFoundation.containers.PointerSizedValues,security.insecureAPI.UncheckedReturn,security.insecureAPI.decodeValueOfObjCType,security.insecureAPI.getpw,security.insecureAPI.gets,security.insecureAPI.mkstemp,security.insecureAPI.mktemp,security.insecureAPI.vfork,unix.API,unix.Malloc,unix.MallocSizeof,unix.MismatchedDeallocator,unix.Vfork,unix.cstring.BadSizeArg,unix.cstring.NullArg")

add_custom_target(ci_clang_analyze
    COMMAND CXX=${CLANG_TOOL} ${CMAKE_COMMAND} -DCMAKE_BUILD_TYPE=Debug -S${PROJECT_SOURCE_DIR} -B${PROJECT_BINARY_DIR}/build_clang_analyze -DJSON_BuildTests=ON -GNinja
    COMMAND cd ${PROJECT_BINARY_DIR}/build_clang_analyze && ${SCAN_BUILD_TOOL} -enable-checker ${CLANG_ANALYZER_CHECKS} --use-c++=${CLANG_TOOL} -analyze-headers -o ${PROJECT_BINARY_DIR}/report ninja
    COMMENT "Check code with Clang Analyzer"
)

###############################################################################
# Check code with Cppcheck.
###############################################################################

add_custom_target(ci_cppcheck
    COMMAND ${CPPCHECK_TOOL} --enable=warning --inline-suppr --inconclusive --force --std=c++11 ${PROJECT_SOURCE_DIR}/single_include/nlohmann/json.hpp --error-exitcode=1
    COMMENT "Check code with Cppcheck"
)

###############################################################################
# Check code with cpplint.
###############################################################################

add_custom_target(ci_cpplint
    COMMAND ${Python3_EXECUTABLE} ${CMAKE_SOURCE_DIR}/third_party/cpplint/cpplint.py --filter=-whitespace,-legal,-runtime/references,-runtime/explicit --quiet --recursive ${SRC_FILES}
    COMMENT "Check code with cpplint"
)

###############################################################################
# Check code with OCLint.
###############################################################################

file(COPY ${PROJECT_SOURCE_DIR}/single_include/nlohmann/json.hpp DESTINATION ${PROJECT_BINARY_DIR}/src_single)
file(RENAME ${PROJECT_BINARY_DIR}/src_single/json.hpp ${PROJECT_BINARY_DIR}/src_single/all.cpp)
file(APPEND "${PROJECT_BINARY_DIR}/src_single/all.cpp" "\n\nint main()\n{}\n")

add_executable(single_all ${PROJECT_BINARY_DIR}/src_single/all.cpp)
target_compile_features(single_all PRIVATE cxx_std_11)

add_custom_target(ci_oclint
    COMMAND ${CMAKE_COMMAND} -DCMAKE_BUILD_TYPE=Debug -S${PROJECT_SOURCE_DIR} -B${PROJECT_BINARY_DIR}/build_oclint -DJSON_BuildTests=OFF -DJSON_CI=ON -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
    COMMAND ${OCLINT_TOOL} -i ${PROJECT_BINARY_DIR}/src_single/all.cpp -p ${PROJECT_BINARY_DIR}/build_oclint -- -report-type html -enable-global-analysis -o oclint_report.html
    COMMENT "Check code with OCLint"
)

###############################################################################
# Check code with Clang-Tidy.
###############################################################################

add_custom_target(ci_clang_tidy
    COMMAND CXX=${CLANG_TOOL} ${CMAKE_COMMAND} -DCMAKE_BUILD_TYPE=Debug -S${PROJECT_SOURCE_DIR} -B${PROJECT_BINARY_DIR}/build_clang_tidy -DJSON_BuildTests=ON -DJSON_MultipleHeaders=ON -GNinja -DCMAKE_EXPORT_COMPILE_COMMANDS=ON -DCMAKE_CXX_CLANG_TIDY=clang-tidy
    COMMAND ${CMAKE_COMMAND} --build ${PROJECT_BINARY_DIR}/build_clang_tidy
    COMMENT "Check code with Clang-Tidy"
)

###############################################################################
# Check code with PVS-Studio Analyzer <https://www.viva64.com/en/pvs-studio/>.
###############################################################################

add_custom_target(ci_pvs_studio
    COMMAND CXX=${CLANG_TOOL} ${CMAKE_COMMAND} -DCMAKE_BUILD_TYPE=Debug -S${PROJECT_SOURCE_DIR} -B${PROJECT_BINARY_DIR}/build_pvs_studio -DJSON_BuildTests=ON -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
    COMMAND cd ${PROJECT_BINARY_DIR}/build_pvs_studio && ${PVS_STUDIO_ANALYZER_TOOL} analyze -j 10
    COMMAND cd ${PROJECT_BINARY_DIR}/build_pvs_studio && ${PLOG_CONVERTER_TOOL} -a'GA:1,2;64:1;CS' -t fullhtml PVS-Studio.log -o pvs
    COMMENT "Check code with PVS Studio"
)

###############################################################################
# Check code with Infer <https://fbinfer.com> static analyzer.
###############################################################################

add_custom_target(ci_infer
    COMMAND mkdir -p ${PROJECT_BINARY_DIR}/build_infer
    COMMAND cd ${PROJECT_BINARY_DIR}/build_infer && ${INFER_TOOL} compile -- ${CMAKE_COMMAND} -DCMAKE_BUILD_TYPE=Debug ${PROJECT_SOURCE_DIR} -DJSON_BuildTests=ON -DJSON_MultipleHeaders=ON
    COMMAND cd ${PROJECT_BINARY_DIR}/build_infer && ${INFER_TOOL} run -- make -j10
    COMMENT "Check code with Infer"
)

###############################################################################
# Check if every header in the include folder includes sufficient headers to
# be compiled individually.
###############################################################################

set(iwyu_path_and_options ${IWYU_TOOL} -Xiwyu --max_line_length=300)

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
    set_property(TARGET single_${RELATIVE_SRC_FILE} PROPERTY CXX_INCLUDE_WHAT_YOU_USE "${iwyu_path_and_options}")
    # remember binary for ci_single_binaries target
    list(APPEND single_binaries single_${RELATIVE_SRC_FILE})
endforeach()

add_custom_target(ci_single_binaries
    DEPENDS ${single_binaries}
    COMMENT "Check if headers are self-contained"
)

###############################################################################
# Benchmarks
###############################################################################

add_custom_target(ci_benchmarks
    COMMAND ${CMAKE_COMMAND} -DCMAKE_BUILD_TYPE=Release -S${PROJECT_SOURCE_DIR}/benchmarks -B${PROJECT_BINARY_DIR}/build_benchmarks
    COMMAND ${CMAKE_COMMAND} --build ${PROJECT_BINARY_DIR}/build_benchmarks --target json_benchmarks
    COMMAND cd ${PROJECT_BINARY_DIR}/build_benchmarks && ./json_benchmarks
    COMMENT "Run benchmarks"
)

###############################################################################
# CMake flags
###############################################################################

if (APPLE)
    set(CMAKE_310_BINARY ${PROJECT_BINARY_DIR}/cmake-3.1.0-Darwin64/CMake.app/Contents/bin/cmake)
    add_custom_command(
        OUTPUT ${CMAKE_310_BINARY}
        COMMAND wget https://github.com/Kitware/CMake/releases/download/v3.1.0/cmake-3.1.0-Darwin64.tar.gz
        COMMAND tar xfz cmake-3.1.0-Darwin64.tar.gz
        COMMAND rm cmake-3.1.0-Darwin64.tar.gz
        WORKING_DIRECTORY ${PROJECT_BINARY_DIR}
        COMMENT "Download CMake 3.1.0"
    )
else()
    set(CMAKE_310_BINARY ${PROJECT_BINARY_DIR}/cmake-3.1.0-Linux-x86_64/bin/cmake)
    add_custom_command(
        OUTPUT ${CMAKE_310_BINARY}
        COMMAND wget https://github.com/Kitware/CMake/releases/download/v3.1.0/cmake-3.1.0-Linux-x86_64.tar.gz
        COMMAND tar xfz cmake-3.1.0-Linux-x86_64.tar.gz
        COMMAND rm cmake-3.1.0-Linux-x86_64.tar.gz
        WORKING_DIRECTORY ${PROJECT_BINARY_DIR}
        COMMENT "Download CMake 3.1.0"
    )
endif()

set(JSON_CMAKE_FLAGS "JSON_BuildTests;JSON_Install;JSON_MultipleHeaders;JSON_Sanitizer;JSON_Valgrind;JSON_NoExceptions;JSON_Coverage")

foreach(JSON_CMAKE_FLAG ${JSON_CMAKE_FLAGS})
    string(TOLOWER "ci_cmake_flag_${JSON_CMAKE_FLAG}" JSON_CMAKE_FLAG_TARGET)
    add_custom_target("${JSON_CMAKE_FLAG_TARGET}"
        COMMENT "Check CMake flag ${JSON_CMAKE_FLAG} (CMake ${CMAKE_VERSION})"
        COMMAND ${CMAKE_COMMAND} -Werror=dev -S${PROJECT_SOURCE_DIR} -B${PROJECT_BINARY_DIR}/build_${JSON_CMAKE_FLAG_TARGET} -D${JSON_CMAKE_FLAG}=ON
    )
    add_custom_target("${JSON_CMAKE_FLAG_TARGET}_31"
        COMMENT "Check CMake flag ${JSON_CMAKE_FLAG} (CMake 3.1)"
        COMMAND mkdir ${PROJECT_BINARY_DIR}/build_${JSON_CMAKE_FLAG_TARGET}_31
        COMMAND cd ${PROJECT_BINARY_DIR}/build_${JSON_CMAKE_FLAG_TARGET}_31 && ${CMAKE_310_BINARY} -Werror=dev ${PROJECT_SOURCE_DIR} -D${JSON_CMAKE_FLAG}=ON -DCMAKE_CXX_COMPILE_FEATURES="cxx_range_for" -DCMAKE_CXX_FLAGS="-std=gnu++11"
        DEPENDS ${CMAKE_310_BINARY}
    )
    list(APPEND JSON_CMAKE_FLAG_TARGETS ${JSON_CMAKE_FLAG_TARGET} ${JSON_CMAKE_FLAG_TARGET}_31)
    list(APPEND JSON_CMAKE_FLAG_BUILD_DIRS ${PROJECT_BINARY_DIR}/build_${JSON_CMAKE_FLAG_TARGET} ${PROJECT_BINARY_DIR}/build_${JSON_CMAKE_FLAG_TARGET}_31)
endforeach()

add_custom_target(ci_cmake_flags
    DEPENDS ${JSON_CMAKE_FLAG_TARGETS}
    COMMENT "Check CMake flags"
)

###############################################################################
# Clean up all generated files.
###############################################################################

add_custom_target(ci_clean
    COMMAND rm -fr ${PROJECT_BINARY_DIR}/build_gcc ${PROJECT_BINARY_DIR}/build_clang ${PROJECT_BINARY_DIR}/build_clang_analyze ${PROJECT_BINARY_DIR}/build_clang_tidy ${PROJECT_BINARY_DIR}/build_pvs_studio ${PROJECT_BINARY_DIR}/build_clang_sanitizer ${PROJECT_BINARY_DIR}/build_valgrind ${PROJECT_BINARY_DIR}/build_infer ${PROJECT_BINARY_DIR}/build_oclint ${PROJECT_BINARY_DIR}/build_benchmarks cmake-3.1.0-Darwin64 ${JSON_CMAKE_FLAG_BUILD_DIRS} ${single_binaries}
    COMMENT "Clean generated directories"
)
