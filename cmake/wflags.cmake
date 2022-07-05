# Ignored Clang warnings:
# -Wno-c++98-compat               The library targets C++11.
# -Wno-c++98-compat-pedantic      The library targets C++11.
# -Wno-deprecated-declarations    The library contains annotations for deprecated functions.
# -Wno-extra-semi-stmt            The library uses std::assert which triggers this warning.
# -Wno-padded                     We do not care about padding warnings.
# -Wno-covered-switch-default     All switches list all cases and a default case.
# -Wno-weak-vtables               The library is header-only.
# -Wreserved-identifier           See https://github.com/onqtam/doctest/issues/536.

set(CLANG_CXXFLAGS
    -Werror
    -Weverything
    -Wno-c++98-compat
    -Wno-c++98-compat-pedantic
    -Wno-deprecated-declarations
    -Wno-extra-semi-stmt
    -Wno-padded
    -Wno-covered-switch-default
    -Wno-weak-vtables
    -Wno-reserved-identifier
)

# Warning flags determined for GCC 13.0 (experimental) with https://github.com/nlohmann/gcc_flags:
# Use the following oneliner to flatten GCC flags:
#     awk 'BEGIN { x=0 } /GCC_CXXFLAGS/ { x=1 } /\)/ { x=0 } \
#         /^\s*-/ { gsub(/ /, "", $0); if(x==1) print }' wflags.cmake | sort
# Ignored GCC warnings:
# -Wno-abi-tag                    We do not care about ABI tags.
# -Wno-aggregate-return           The library uses aggregate returns.
# -Wno-long-long                  The library uses the long long type to interface with system functions.
# -Wno-namespaces                 The library uses namespaces.
# -Wno-padded                     We do not care about padding warnings.
# -Wno-system-headers             We do not care about warnings in system headers.
# -Wno-templates                  The library uses templates.

set(GCC_CXXFLAGS
    -pedantic
    -Werror
    -Wno-abi-tag
    -Waddress
    -Wno-aggregate-return
    -Waggressive-loop-optimizations
    -Waligned-new=all
    -Wall
    -Walloc-zero
    -Walloca
    -Warray-bounds=2
    -Wattributes
    -Wbool-compare
    -Wbool-operation
    -Wbuiltin-declaration-mismatch
    -Wbuiltin-macro-redefined
    -Wc++0x-compat
    -Wc++11-compat
    -Wc++14-compat
    -Wc++17-compat
    -Wc++1z-compat
    -Wcast-align
    -Wcast-align=strict
    -Wcast-function-type
    -Wcast-qual
    -Wcatch-value=3
    -Wchar-subscripts
    -Wclass-memaccess
    -Wclobbered
    -Wcomment
    -Wcomments
    -Wconditionally-supported
    -Wconversion
    -Wconversion-null
    -Wcoverage-mismatch
    -Wcpp
    -Wctor-dtor-privacy
    -Wdangling-else
    -Wdate-time
    -Wdelete-incomplete
    -Wdelete-non-virtual-dtor
    -Wdeprecated
    -Wdeprecated-declarations
    -Wdisabled-optimization
    -Wdiv-by-zero
    -Wdouble-promotion
    -Wduplicated-branches
    -Wduplicated-cond
    -Weffc++
    -Wempty-body
    -Wendif-labels
    -Wenum-compare
    -Wexpansion-to-defined
    -Wextra
    -Wextra-semi
    -Wfloat-conversion
    -Wfloat-equal
    -Wformat-overflow=2
    -Wformat-signedness
    -Wformat-truncation=2
    -Wformat=2
    -Wframe-address
    -Wfree-nonheap-object
    -Whsa
    -Wif-not-aligned
    -Wignored-attributes
    -Wignored-qualifiers
    -Wimplicit-fallthrough=5
    -Winherited-variadic-ctor
    -Winit-self
    -Winline
    -Wint-in-bool-context
    -Wint-to-pointer-cast
    -Winvalid-memory-model
    -Winvalid-offsetof
    -Winvalid-pch
    -Wliteral-suffix
    -Wlogical-not-parentheses
    -Wlogical-op
    -Wno-long-long
    -Wlto-type-mismatch
    -Wmain
    -Wmaybe-uninitialized
    -Wmemset-elt-size
    -Wmemset-transposed-args
    -Wmisleading-indentation
    -Wmissing-attributes
    -Wmissing-braces
    -Wmissing-declarations
    -Wmissing-field-initializers
    -Wmissing-include-dirs
    -Wmultichar
    -Wmultiple-inheritance
    -Wmultistatement-macros
    -Wno-namespaces
    -Wnarrowing
    -Wnoexcept
    -Wnoexcept-type
    -Wnon-template-friend
    -Wnon-virtual-dtor
    -Wnonnull
    -Wnonnull-compare
    -Wnormalized=nfkc
    -Wnull-dereference
    -Wodr
    -Wold-style-cast
    -Wopenmp-simd
    -Woverflow
    -Woverlength-strings
    -Woverloaded-virtual
    -Wpacked
    -Wpacked-bitfield-compat
    -Wpacked-not-aligned
    -Wno-padded
    -Wparentheses
    -Wpedantic
    -Wplacement-new=2
    -Wpmf-conversions
    -Wpointer-arith
    -Wpointer-compare
    -Wpragmas
    -Wpsabi
    -Wredundant-decls
    -Wregister
    -Wreorder
    -Wrestrict
    -Wreturn-local-addr
    -Wreturn-type
    -Wscalar-storage-order
    -Wsequence-point
    -Wshadow=compatible-local
    -Wshadow=global
    -Wshadow=local
    -Wshift-count-negative
    -Wshift-count-overflow
    -Wshift-negative-value
    -Wshift-overflow=2
    -Wsign-compare
    -Wsign-conversion
    -Wsign-promo
    -Wsized-deallocation
    -Wsizeof-array-argument
    -Wsizeof-pointer-div
    -Wsizeof-pointer-memaccess
    -Wstack-protector
    -Wstrict-aliasing=3
    -Wstrict-null-sentinel
    -Wno-strict-overflow    
    -Wstringop-overflow=4
    -Wstringop-truncation
    -Wsubobject-linkage
    -Wsuggest-attribute=cold
    -Wsuggest-attribute=const
    -Wsuggest-attribute=format
    -Wsuggest-attribute=malloc
    -Wsuggest-attribute=noreturn
    -Wsuggest-attribute=pure
    -Wsuggest-final-methods
    -Wsuggest-final-types
    -Wsuggest-override
    -Wswitch
    -Wswitch-bool
    -Wswitch-default
    -Wswitch-enum    
    -Wswitch-unreachable
    -Wsync-nand
    -Wsynth
    -Wno-system-headers
    -Wtautological-compare
    -Wno-templates
    -Wterminate
    -Wtrampolines
    -Wtrigraphs
    -Wtype-limits
    -Wundef
    -Wuninitialized
    -Wunknown-pragmas
    -Wunreachable-code
    -Wunsafe-loop-optimizations
    -Wunused
    -Wunused-but-set-parameter
    -Wunused-but-set-variable
    -Wunused-const-variable=2
    -Wunused-function
    -Wunused-label
    -Wunused-local-typedefs
    -Wunused-parameter
    -Wunused-result
    -Wunused-value
    -Wunused-variable
    -Wuseless-cast
    -Wvarargs
    -Wvariadic-macros
    -Wvector-operation-performance
    -Wvirtual-inheritance
    -Wvirtual-move-assign
    -Wvla
    -Wvolatile-register-var
    -Wwrite-strings
    -Wzero-as-null-pointer-constant
)

if(CMAKE_CXX_COMPILER_VERSION VERSION_GREATER_EQUAL 9.0.0)
    list(APPEND GCC_CXXFLAGS
        -Waddress-of-packed-member
        -Wattribute-alias=2
        -Wattribute-warning
        -Wcannot-profile
        -Wclass-conversion
        -Wdeprecated-copy
        -Wdeprecated-copy-dtor
        -Winit-list-lifetime
        -Wmissing-profile
        -Wpessimizing-move
        -Wprio-ctor-dtor
        -Wredundant-move
    )
endif()

if(CMAKE_CXX_COMPILER_VERSION VERSION_GREATER_EQUAL 10.0.0)
    list(APPEND GCC_CXXFLAGS
        -Wanalyzer-double-fclose
        -Wanalyzer-double-free
        -Wanalyzer-exposure-through-output-file
        -Wanalyzer-file-leak
        -Wanalyzer-free-of-non-heap
        -Wanalyzer-malloc-leak
        -Wanalyzer-null-argument
        -Wanalyzer-null-dereference
        -Wanalyzer-possible-null-argument
        -Wanalyzer-possible-null-dereference
        -Wanalyzer-stale-setjmp-buffer
        -Wanalyzer-tainted-array-index
        -Wanalyzer-too-complex
        -Wanalyzer-unsafe-call-within-signal-handler
        -Wanalyzer-use-after-free
        -Wanalyzer-use-of-pointer-in-stale-stack-frame
        -Warith-conversion
        -Wc++20-compat
        -Wc++2a-compat
        -Wcomma-subscript
        -Wformat-diag
        -Winaccessible-base
        -Wmismatched-tags
        -Wredundant-tags
        -Wstring-compare
        -Wswitch-outside-range
        # available earlier but generates a lot more warnings before GCC 10
        -Wunused-macros
        -Wvolatile
        -Wzero-length-bounds
    )
endif()

if(CMAKE_CXX_COMPILER_VERSION VERSION_GREATER_EQUAL 11.0.0)
    list(APPEND GCC_CXXFLAGS
        -WNSObject-attribute
        -Wanalyzer-mismatching-deallocation
        -Wanalyzer-shift-count-negative
        -Wanalyzer-shift-count-overflow
        -Wanalyzer-write-to-const
        -Wanalyzer-write-to-string-literal
        -Warray-parameter=2
        -Wctad-maybe-unsupported
        -Wdeprecated-enum-enum-conversion
        -Wdeprecated-enum-float-conversion
        -Wexceptions
        -Wenum-conversion
        -Winvalid-imported-macros
        -Wmismatched-dealloc
        -Wmismatched-new-delete
        -Wrange-loop-construct
        -Wsizeof-array-div
        -Wstringop-overread
        -Wtsan
        -Wvexing-parse
        -Wvla-parameter
    )
endif()

if(CMAKE_CXX_COMPILER_VERSION VERSION_GREATER_EQUAL 12.0.0)
    list(APPEND GCC_CXXFLAGS
        -Wanalyzer-tainted-allocation-size
        -Wanalyzer-tainted-divisor
        -Wanalyzer-tainted-offset
        -Wanalyzer-tainted-size
        -Wanalyzer-use-of-uninitialized-value
        -Warray-compare
        -Wc++11-extensions
        -Wc++14-extensions
        -Wc++17-extensions
        -Wc++20-extensions
        -Wc++23-extensions
        -Wcoverage-invalid-line-number
        -Wdangling-pointer=2
        -Winfinite-recursion
        -Winterference-size
        -Wmissing-requires
        -Wmissing-template-keyword
        -Wopenacc-parallelism
        -Wtrivial-auto-var-init
        -Wuse-after-free=3
    )
endif()

if(CMAKE_CXX_COMPILER_VERSION VERSION_GREATER_EQUAL 13.0.0)
    list(APPEND GCC_CXXFLAGS
        -Wanalyzer-va-arg-type-mismatch
        -Wanalyzer-va-list-exhausted
        -Wanalyzer-va-list-leak
        -Wanalyzer-va-list-use-after-va-end
    )
endif()
