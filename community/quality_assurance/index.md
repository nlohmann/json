# Quality assurance

Ensuring quality is paramount for this project, particularly because [numerous other projects](https://json.nlohmann.me/home/customers/index.md) depend on it. Each commit to the library undergoes rigorous checks against the following requirements, and any violations will result in a failed build.

## C++ language compliance and compiler compatibility

Requirement: Compiler support

Any compiler with complete C++11 support can compile the library without warnings.

Note: C++20 modules support may hit compiler-specific issues not covered by the general compiler matrix below. See [Modules](https://json.nlohmann.me/features/modules/#known-issues) for known issues and workarounds.

Note: Some modern features (like C++20 ranges or filesystem support) may be disabled on specific broken or incomplete toolchains even when standard feature-test macros indicate support. See [`JSON_HAS_RANGES`](https://json.nlohmann.me/api/macros/json_has_ranges/index.md) and [`JSON_HAS_FILESYSTEM`](https://json.nlohmann.me/api/macros/json_has_filesystem/index.md) for details on known exclusions.

- The library is compiled with 50+ different C++ compilers with different operating systems and platforms, including the oldest versions known to compile the library.

  Compilers used in continuous integration

  | Compiler                                     | Architecture | Operating System                  | CI        |
  | -------------------------------------------- | ------------ | --------------------------------- | --------- |
  | AppleClang 15.0.0.15000040; Xcode 15.0.1     | arm64        | macOS 14.7.2 (Sonoma)             | GitHub    |
  | AppleClang 15.0.0.15000100; Xcode 15.1       | arm64        | macOS 14.7.2 (Sonoma)             | GitHub    |
  | AppleClang 15.0.0.15000100; Xcode 15.2       | arm64        | macOS 14.7.2 (Sonoma)             | GitHub    |
  | AppleClang 15.0.0.15000309; Xcode 15.3       | arm64        | macOS 14.7.2 (Sonoma)             | GitHub    |
  | AppleClang 15.0.0.15000309; Xcode 15.4       | arm64        | macOS 14.7.2 (Sonoma)             | GitHub    |
  | AppleClang 16.0.0.16000026; Xcode 16         | arm64        | macOS 15.2 (Sequoia)              | GitHub    |
  | AppleClang 16.0.0.16000026; Xcode 16.1       | arm64        | macOS 15.2 (Sequoia)              | GitHub    |
  | AppleClang 16.0.0.16000026; Xcode 16.2       | arm64        | macOS 15.2 (Sequoia)              | GitHub    |
  | AppleClang 17.0.0.17000013; Xcode 16.3       | arm64        | macOS 15.5 (Sequoia)              | GitHub    |
  | AppleClang 17.0.0.17000013; Xcode 16.4       | arm64        | macOS 15.5 (Sequoia)              | GitHub    |
  | AppleClang 17.0.0.17000319; Xcode 26.0.1     | arm64        | macOS 15.5 (Sequoia)              | GitHub    |
  | Clang 3.4.2                                  | x86_64       | Ubuntu 22.04.1 LTS                | GitHub    |
  | Clang 3.5.2                                  | x86_64       | Ubuntu 22.04.1 LTS                | GitHub    |
  | Clang 3.6.2                                  | x86_64       | Ubuntu 22.04.1 LTS                | GitHub    |
  | Clang 3.7.1                                  | x86_64       | Ubuntu 22.04.1 LTS                | GitHub    |
  | Clang 3.8.1                                  | x86_64       | Ubuntu 22.04.1 LTS                | GitHub    |
  | Clang 3.9.1                                  | x86_64       | Ubuntu 22.04.1 LTS                | GitHub    |
  | Clang 4.0.1                                  | x86_64       | Ubuntu 22.04.1 LTS                | GitHub    |
  | Clang 5.0.2                                  | x86_64       | Ubuntu 22.04.1 LTS                | GitHub    |
  | Clang 6.0.1                                  | x86_64       | Ubuntu 22.04.1 LTS                | GitHub    |
  | Clang 7.1.0                                  | x86_64       | Ubuntu 22.04.1 LTS                | GitHub    |
  | Clang 8.0.1                                  | x86_64       | Ubuntu 22.04.1 LTS                | GitHub    |
  | Clang 9.0.1                                  | x86_64       | Ubuntu 22.04.1 LTS                | GitHub    |
  | Clang 10.0.1                                 | x86_64       | Ubuntu 22.04.1 LTS                | GitHub    |
  | Clang 11.0.1 with GNU-like command-line      | x86_64       | Windows Server 2022 (Build 20348) | GitHub    |
  | Clang 11.1.0                                 | x86_64       | Ubuntu 22.04.1 LTS                | GitHub    |
  | Clang 12.0.1 with GNU-like command-line      | x86_64       | Windows Server 2022 (Build 20348) | GitHub    |
  | Clang 12.0.1                                 | x86_64       | Ubuntu 22.04.1 LTS                | GitHub    |
  | Clang 13.0.1 with GNU-like command-line      | x86_64       | Windows Server 2022 (Build 20348) | GitHub    |
  | Clang 13.0.1                                 | x86_64       | Ubuntu 22.04.1 LTS                | GitHub    |
  | Clang 14.0.6                                 | x86_64       | Ubuntu 22.04.1 LTS                | GitHub    |
  | Clang 14.0.6 with GNU-like command-line      | x86_64       | Windows Server 2022 (Build 20348) | GitHub    |
  | Clang 15.0.7                                 | x86_64       | Ubuntu 22.04.1 LTS                | GitHub    |
  | Clang 15.0.7 with GNU-like command-line      | x86_64       | Windows Server 2022 (Build 20348) | GitHub    |
  | Clang 16.0.6                                 | x86_64       | Ubuntu 22.04.1 LTS                | GitHub    |
  | Clang 16.0.6 with GNU-like command-line      | x86_64       | Windows Server 2022 (Build 20348) | GitHub    |
  | Clang 17.0.6                                 | x86_64       | Ubuntu 22.04.1 LTS                | GitHub    |
  | Clang 18.1.8                                 | x86_64       | Ubuntu 22.04.1 LTS                | GitHub    |
  | Clang 18.1.8 with GNU-like command-line      | x86_64       | Windows Server 2022 (Build 20348) | GitHub    |
  | Clang 19.1.5 with MSVC-like command-line     | x86_64       | Windows Server 2022 (Build 20348) | GitHub    |
  | Clang 19.1.7                                 | x86_64       | Ubuntu 22.04.1 LTS                | GitHub    |
  | Clang 19.1.7 with GNU-like command-line      | x86_64       | Windows Server 2022 (Build 20348) | GitHub    |
  | Clang 20.1.1                                 | x86_64       | Ubuntu 22.04.1 LTS                | GitHub    |
  | Clang 20.1.8 with GNU-like command-line      | x86_64       | Windows Server 2022 (Build 20348) | GitHub    |
  | Clang 21.1.8                                 | x86_64       | Ubuntu 22.04.1 LTS                | GitHub    |
  | CUDA 11.8.0 (nvcc)                           | x86_64       | Ubuntu 22.04 LTS                  | GitHub    |
  | CUDA 12.1.1 (nvcc)                           | x86_64       | Ubuntu 22.04 LTS                  | GitHub    |
  | CUDA 12.6.3 (nvcc)                           | x86_64       | Ubuntu 22.04 LTS                  | GitHub    |
  | Emscripten 4.0.6                             | x86_64       | Ubuntu 22.04.1 LTS                | GitHub    |
  | GNU 4.8.5                                    | x86_64       | Ubuntu 22.04.1 LTS                | GitHub    |
  | GNU 4.9.3                                    | x86_64       | Ubuntu 22.04.1 LTS                | GitHub    |
  | GNU 5.5.0                                    | x86_64       | Ubuntu 22.04.1 LTS                | GitHub    |
  | GNU 6.4.0                                    | x86_64       | Ubuntu 22.04.1 LTS                | GitHub    |
  | GNU 7.5.0                                    | x86_64       | Ubuntu 22.04.1 LTS                | GitHub    |
  | GNU 8.5.0                                    | x86_64       | Ubuntu 22.04.1 LTS                | GitHub    |
  | GNU 9.3.0                                    | x86_64       | Ubuntu 22.04.1 LTS                | GitHub    |
  | GNU 9.4.0                                    | x86_64       | Ubuntu 22.04.1 LTS                | GitHub    |
  | GNU 9.5.0                                    | x86_64       | Ubuntu 22.04.1 LTS                | GitHub    |
  | GNU 10.5.0                                   | x86_64       | Ubuntu 22.04.1 LTS                | GitHub    |
  | GNU 11.4.0                                   | x86_64       | Ubuntu 22.04.1 LTS                | GitHub    |
  | GNU 11.5.0                                   | x86_64       | Ubuntu 22.04.1 LTS                | GitHub    |
  | GNU 12.2.0 (MinGW-W64 i686-ucrt-posix-dwarf) | x86_64       | Windows Server 2022 (Build 20348) | GitHub    |
  | GNU 12.2.0 (MinGW-W64 x86_64-ucrt-posix-seh) | x86_64       | Windows Server 2022 (Build 20348) | GitHub    |
  | GNU 12.4.0                                   | x86_64       | Ubuntu 22.04.1 LTS                | GitHub    |
  | GNU 13.3.0                                   | x86_64       | Ubuntu 22.04.1 LTS                | GitHub    |
  | GNU 14.2.0                                   | x86_64       | Ubuntu 22.04.1 LTS                | GitHub    |
  | GNU 15.1.0                                   | x86_64       | Ubuntu 22.04.1 LTS                | GitHub    |
  | GNU 16.1.0                                   | x86_64       | Ubuntu 22.04.1 LTS                | GitHub    |
  | GNU 16.1.0                                   | arm64        | Linux 6.1.100                     | Cirrus CI |
  | icpc (ICC) 2021.5.0 20211109                 | x86_64       | Ubuntu 20.04.3 LTS                | GitHub    |
  | icpx (Intel oneAPI DPC++/C++) 2025.3.2       | x86_64       | Ubuntu 24.04 LTS                  | GitHub    |
  | nvc++ (NVIDIA HPC SDK) 25.5-0                | x86_64       | Ubuntu 22.04 LTS                  | GitHub    |
  | MSVC 19.0.24241.7                            | x86          | Windows 8.1                       | AppVeyor  |
  | MSVC 19.16.27035.0                           | x86          | Windows-10 (Build 14393)          | AppVeyor  |
  | MSVC 19.29.30157.0                           | x86          | Windows-10 (Build 17763)          | AppVeyor  |
  | MSVC 19.44.35207.0                           | arm64        | Windows 11 (Build 26200)          | GitHub    |
  | MSVC 19.44.35214.0                           | x86          | Windows Server 2022 (Build 20348) | GitHub    |
  | MSVC 19.44.35214.0                           | x86_64       | Windows Server 2022 (Build 20348) | GitHub    |
  | MSVC 19.51.36231.0                           | x86          | Windows Server 2025 (Build 26100) | GitHub    |
  | MSVC 19.51.36231.0                           | x86_64       | Windows Server 2025 (Build 26100) | GitHub    |

- The library is compiled with all C++ language revisions (C++11, C++14, C++17, C++20, C++23, and C++26) to detect and fix language deprecations early.

- The library is checked for compiler warnings:

- On Clang, `-Weverything` is used with 8 exceptions.

  Clang warnings

  ```
  # Ignored Clang warnings:
  # -Wno-c++98-compat               The library targets C++11.
  # -Wno-c++98-compat-pedantic      The library targets C++11.
  # -Wno-deprecated-declarations    The library contains annotations for deprecated functions.
  # -Wno-extra-semi-stmt            The library uses assert which triggers this warning.
  # -Wno-padded                     We do not care about padding warnings.
  # -Wno-covered-switch-default     All switches list all cases and a default case.
  # -Wno-unsafe-buffer-usage        Pervasive: the library's own low-level numeric/buffer code
  #                                 (to_chars, serializer, lexer, binary reader/writer, input
  #                                 adapters, json_pointer) plus vendored Doctest itself (~208
  #                                 distinct sites measured 2026-07-08 on clang trunk) all use
  #                                 raw pointer arithmetic / libc string calls by necessity.

  set(CLANG_CXXFLAGS
      -Werror
      -Weverything
      -Wno-c++98-compat
      -Wno-c++98-compat-pedantic
      -Wno-deprecated-declarations
      -Wno-extra-semi-stmt
      -Wno-padded
      -Wno-covered-switch-default
      -Wno-unsafe-buffer-usage
  )
  ```

- On GCC, 300+ warnings are enabled with 8 exceptions.

  GCC warnings

  ```
  # Warning flags determined for GCC 15.1.0 with https://github.com/nlohmann/gcc_flags:
  # Ignored GCC warnings:
  # -Wno-abi-tag           We do not care about ABI tags.
  # -Wno-aggregate-return  The library uses aggregate returns.
  # -Wno-long-long         The library uses the long long type to interface with system functions.
  # -Wno-namespaces        The library uses namespaces.
  # -Wno-nrvo              Doctest triggers this warning.
  # -Wno-padded            We do not care about padding warnings.
  # -Wno-system-headers    We do not care about warnings in system headers.
  # -Wno-templates         The library uses templates.

  set(GCC_CXXFLAGS
      -pedantic
      -Werror
      --all-warnings
      --extra-warnings
      -W
      -WNSObject-attribute
      -Wno-abi-tag
      -Waddress
      -Waddress-of-packed-member
      -Wno-aggregate-return
      -Waggressive-loop-optimizations
      -Waligned-new=all
      -Wall
      -Walloc-size
      -Walloc-zero
      -Walloca
      -Wanalyzer-allocation-size
      -Wanalyzer-deref-before-check
      -Wanalyzer-double-fclose
      -Wanalyzer-double-free
      -Wanalyzer-exposure-through-output-file
      -Wanalyzer-exposure-through-uninit-copy
      -Wanalyzer-fd-access-mode-mismatch
      -Wanalyzer-fd-double-close
      -Wanalyzer-fd-leak
      -Wanalyzer-fd-phase-mismatch
      -Wanalyzer-fd-type-mismatch
      -Wanalyzer-fd-use-after-close
      -Wanalyzer-fd-use-without-check
      -Wanalyzer-file-leak
      -Wanalyzer-free-of-non-heap
      -Wanalyzer-imprecise-fp-arithmetic
      -Wanalyzer-infinite-loop
      -Wanalyzer-infinite-recursion
      -Wanalyzer-jump-through-null
      -Wanalyzer-malloc-leak
      -Wanalyzer-mismatching-deallocation
      -Wanalyzer-null-argument
      -Wanalyzer-null-dereference
      -Wanalyzer-out-of-bounds
      -Wanalyzer-overlapping-buffers
      -Wanalyzer-possible-null-argument
      -Wanalyzer-possible-null-dereference
      -Wanalyzer-putenv-of-auto-var
      -Wanalyzer-shift-count-negative
      -Wanalyzer-shift-count-overflow
      -Wanalyzer-stale-setjmp-buffer
      -Wanalyzer-symbol-too-complex
      -Wanalyzer-tainted-allocation-size
      -Wanalyzer-tainted-array-index
      -Wanalyzer-tainted-assertion
      -Wanalyzer-tainted-divisor
      -Wanalyzer-tainted-offset
      -Wanalyzer-tainted-size
      -Wanalyzer-too-complex
      -Wanalyzer-undefined-behavior-ptrdiff
      -Wanalyzer-undefined-behavior-strtok
      -Wanalyzer-unsafe-call-within-signal-handler
      -Wanalyzer-use-after-free
      -Wanalyzer-use-of-pointer-in-stale-stack-frame
      -Wanalyzer-use-of-uninitialized-value
      -Wanalyzer-va-arg-type-mismatch
      -Wanalyzer-va-list-exhausted
      -Wanalyzer-va-list-leak
      -Wanalyzer-va-list-use-after-va-end
      -Wanalyzer-write-to-const
      -Wanalyzer-write-to-string-literal
      -Warith-conversion
      -Warray-bounds=2
      -Warray-compare
      -Warray-parameter=2
      -Wattribute-alias=2
      -Wattribute-warning
      -Wattributes
      -Wbool-compare
      -Wbool-operation
      -Wbuiltin-declaration-mismatch
      -Wbuiltin-macro-redefined
      -Wc++0x-compat
      -Wc++11-compat
      -Wc++11-extensions
      -Wc++14-compat
      -Wc++14-extensions
      -Wc++17-compat
      -Wc++17-extensions
      -Wc++1z-compat
      -Wc++20-compat
      -Wc++20-extensions
      -Wc++23-extensions
      -Wc++26-extensions
      -Wc++2a-compat
      -Wcalloc-transposed-args
      -Wcannot-profile
      -Wcast-align
      -Wcast-align=strict
      -Wcast-function-type
      -Wcast-qual
      -Wcast-user-defined
      -Wcatch-value=3
      -Wchanges-meaning
      -Wchar-subscripts
      -Wclass-conversion
      -Wclass-memaccess
      -Wclobbered
      -Wcomma-subscript
      -Wcomment
      -Wcomments
      -Wcomplain-wrong-lang
      -Wconditionally-supported
      -Wconversion
      -Wconversion-null
      -Wcoverage-invalid-line-number
      -Wcoverage-mismatch
      -Wcoverage-too-many-conditions
      -Wcoverage-too-many-paths
      -Wcpp
      -Wctad-maybe-unsupported
      -Wctor-dtor-privacy
      -Wdangling-else
      -Wdangling-pointer=2
      -Wdangling-reference
      -Wdate-time
      -Wdefaulted-function-deleted
      -Wdelete-incomplete
      -Wdelete-non-virtual-dtor
      -Wdeprecated
      -Wdeprecated-copy
      -Wdeprecated-copy-dtor
      -Wdeprecated-declarations
      -Wdeprecated-enum-enum-conversion
      -Wdeprecated-enum-float-conversion
      -Wdeprecated-literal-operator
      -Wdeprecated-variadic-comma-omission
      -Wdisabled-optimization
      -Wdiv-by-zero
      -Wdouble-promotion
      -Wduplicated-branches
      -Wduplicated-cond
      -Weffc++
      -Welaborated-enum-base
      -Wempty-body
      -Wendif-labels
      -Wenum-compare
      -Wenum-conversion
      -Wexceptions
      -Wexpansion-to-defined
      -Wextra
      -Wextra-semi
      -Wflex-array-member-not-at-end
      -Wfloat-conversion
      -Wfloat-equal
      -Wformat -Wformat-contains-nul
      -Wformat -Wformat-diag
      -Wformat -Wformat-extra-args
      -Wformat -Wformat-nonliteral
      -Wformat -Wformat-overflow=2
      -Wformat -Wformat-security
      -Wformat -Wformat-signedness
      -Wformat -Wformat-truncation=2
      -Wformat -Wformat-y2k
      -Wformat -Wformat-zero-length
      -Wformat=2
      -Wframe-address
      -Wfree-nonheap-object
      -Wglobal-module
      -Whardened
      -Wheader-guard
      -Whsa
      -Wif-not-aligned
      -Wignored-attributes
      -Wignored-qualifiers
      -Wimplicit-fallthrough=5
      -Winaccessible-base
      -Winfinite-recursion
      -Winherited-variadic-ctor
      -Winit-list-lifetime
      -Winit-self
      -Winline
      -Wint-in-bool-context
      -Wint-to-pointer-cast
      -Winterference-size
      -Winvalid-constexpr
      -Winvalid-imported-macros
      -Winvalid-memory-model
      -Winvalid-offsetof
      -Winvalid-pch
      -Winvalid-utf8
      -Wliteral-suffix
      -Wlogical-not-parentheses
      -Wlogical-op
      -Wno-long-long
      -Wlto-type-mismatch
      -Wmain
      -Wmaybe-musttail-local-addr
      -Wmaybe-uninitialized
      -Wmemset-elt-size
      -Wmemset-transposed-args
      -Wmisleading-indentation
      -Wmismatched-dealloc
      -Wmismatched-new-delete
      -Wmismatched-tags
      -Wmissing-attributes
      -Wmissing-braces
      -Wmissing-declarations
      -Wmissing-field-initializers
      -Wmissing-include-dirs
      -Wmissing-profile
      -Wmissing-requires
      -Wmissing-template-keyword
      -Wmultichar
      -Wmultiple-inheritance
      -Wmultistatement-macros
      -Wmusttail-local-addr
      -Wno-namespaces
      -Wnarrowing
      -Wnoexcept
      -Wnoexcept-type
      -Wnon-template-friend
      -Wnon-virtual-dtor
      -Wnonnull
      -Wnonnull-compare
      -Wnormalized=nfkc
      -Wno-nrvo
      -Wnull-dereference
      -Wodr
      -Wold-style-cast
      -Wopenacc-parallelism
      -Wopenmp
      -Wopenmp-simd
      -Woverflow
      -Woverlength-strings
      -Woverloaded-virtual=2
      -Wpacked
      -Wpacked-bitfield-compat
      -Wpacked-not-aligned
      -Wno-padded
      -Wparentheses
      -Wpedantic
      -Wpessimizing-move
      -Wplacement-new=2
      -Wpmf-conversions
      -Wpointer-arith
      -Wpointer-compare
      -Wpragma-once-outside-header
      -Wpragmas
      -Wprio-ctor-dtor
      -Wpsabi
      -Wrange-loop-construct
      -Wredundant-decls
      -Wredundant-move
      -Wredundant-tags
      -Wregister
      -Wreorder
      -Wrestrict
      -Wreturn-local-addr
      -Wreturn-type
      -Wscalar-storage-order
      -Wself-move
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
      -Wsizeof-array-div
      -Wsizeof-pointer-div
      -Wsizeof-pointer-memaccess
      -Wstack-protector
      -Wstrict-aliasing
      -Wstrict-aliasing=3
      -Wstrict-null-sentinel
      -Wstrict-overflow
      -Wstring-compare
      -Wstringop-overflow
      -Wstringop-overflow=4
      -Wstringop-overread
      -Wstringop-truncation
      -Wsubobject-linkage
      -Wsuggest-attribute=cold
      -Wsuggest-attribute=const
      -Wsuggest-attribute=format
      -Wsuggest-attribute=malloc
      -Wsuggest-attribute=noreturn
      -Wsuggest-attribute=pure
      -Wsuggest-attribute=returns_nonnull
      -Wsuggest-final-methods
      -Wsuggest-final-types
      -Wsuggest-override
      -Wswitch
      -Wswitch-bool
      -Wswitch-default
      -Wswitch-enum
      -Wswitch-outside-range
      -Wswitch-unreachable
      -Wsync-nand
      -Wsynth
      -Wno-system-headers
      -Wtautological-compare
      -Wtemplate-body
      -Wtemplate-id-cdtor
      -Wtemplate-names-tu-local
      -Wno-templates
      -Wterminate
      -Wtrailing-whitespace
      -Wtrampolines
      -Wtrigraphs
      -Wtrivial-auto-var-init
      -Wtsan
      -Wtype-limits
      -Wundef
      -Wunicode
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
      -Wunused-macros
      -Wunused-parameter
      -Wunused-result
      -Wunused-value
      -Wunused-variable
      -Wuse-after-free=3
      -Wuseless-cast
      -Wvarargs
      -Wvariadic-macros
      -Wvector-operation-performance
      -Wvexing-parse
      -Wvirtual-inheritance
      -Wvirtual-move-assign
      -Wvla
      -Wvla-parameter
      -Wvolatile
      -Wvolatile-register-var
      -Wwrite-strings
      -Wxor-used-as-pow
      -Wzero-as-null-pointer-constant
      -Wzero-length-bounds
  )
  ```

## C++ standard library compliance

Requirement: No prerequisites

The library has no prerequisites other than the Standard Template Library (STL).

- The library is compiled and tested with both [libc++](https://libcxx.llvm.org) and [libstdc++](https://gcc.gnu.org/onlinedocs/libstdc++/) to detect subtle differences or incompatibilities.
- The code checked with [Include What You Use (IWYU)](https://include-what-you-use.org) that all required standard headers are included.
- On Windows, the library is compiled with `<Windows.h>` being included to detect and avoid common bugs.
- The library is compiled with exceptions disabled to support alternative means of error handling.

## Stable public API

Requirement: Stable public API

Any change to the library does not break the public API.

- All public API functions are tested with a variety of arguments.
- The library is compiled and tested with different template arguments for number, string, array, and object types.
- Unit tests cover all lines of the code base.
- Every exception of the library is thrown in the test suite, and the error messages and exception ids are checked.

Requirement: Complete documentation

The public API is extensively documented.

- Every public API function has a dedicated page in the [API reference documentation](https://json.nlohmann.me/api/basic_json/) with a self-contained code example.
- All examples in the documentation are tested, and changes in their output are treated as an error.

## Robust input processing

Requirement: Standards compliance

The library is compliant to JSON as defined in [RFC 8259](https://datatracker.ietf.org/doc/html/rfc8259).

- The lexer is tested with all valid Unicode code points and all prefixes of all invalid Unicode code points.
- The parser is tested against extensive correctness suites for JSON compliance.
- In addition, the library is continuously fuzz-tested at [OSS-Fuzz](https://google.github.io/oss-fuzz/) where the library is checked against billions of inputs.

## Static analysis

Requirement: State-of-the-art code analysis

The code is checked with state-of-the-art static code analysis tools.

- The code is checked with the latest [Clang-Tidy](https://clang.llvm.org/extra/clang-tidy/).

  Clang-Tidy configuration (.clang-tidy)

  ```
  # TODO: The first three checks are only removed to get the CI going. They have to be addressed at some point.
  # TODO: portability-avoid-pragma-once: should be fixed eventually

  Checks: '*,

           -portability-template-virtual-member-function,
           -bugprone-use-after-move,
           -hicpp-invalid-access-moved,

           -altera-id-dependent-backward-branch,
           -altera-struct-pack-align,
           -altera-unroll-loops,
           -android-cloexec-fopen,
           -boost-use-ranges,
           -bugprone-easily-swappable-parameters,
           -cert-err58-cpp,
           -clang-analyzer-webkit.NoUncountedMemberChecker,
           -concurrency-mt-unsafe,
           -cppcoreguidelines-avoid-const-or-ref-data-members,
           -cppcoreguidelines-avoid-do-while,
           -cppcoreguidelines-avoid-goto,
           -cppcoreguidelines-avoid-magic-numbers,
           -cppcoreguidelines-avoid-non-const-global-variables,
           -cppcoreguidelines-macro-usage,
           -cppcoreguidelines-pro-bounds-avoid-unchecked-container-access,
           -cppcoreguidelines-pro-bounds-array-to-pointer-decay,
           -cppcoreguidelines-pro-bounds-constant-array-index,
           -cppcoreguidelines-pro-bounds-pointer-arithmetic,
           -cppcoreguidelines-pro-type-reinterpret-cast,
           -cppcoreguidelines-pro-type-union-access,
           -cppcoreguidelines-rvalue-reference-param-not-moved,
           -cppcoreguidelines-virtual-class-destructor,
           -fuchsia-default-arguments-calls,
           -fuchsia-default-arguments-declarations,
           -fuchsia-overloaded-operator,
           -google-explicit-constructor,
           -google-readability-function-size,
           -google-runtime-float,
           -google-runtime-int,
           -google-runtime-references,
           -hicpp-avoid-goto,
           -hicpp-explicit-conversions,
           -hicpp-function-size,
           -hicpp-no-array-decay,
           -hicpp-no-assembler,
           -hicpp-signed-bitwise,
           -hicpp-uppercase-literal-suffix,
           -llvm-header-guard,
           -llvm-include-order,
           -llvm-prefer-static-over-anonymous-namespace,
           -llvm-use-ranges,
           -llvmlibc-*,
           -misc-use-anonymous-namespace,
           -misc-confusable-identifiers,
           -misc-include-cleaner,
           -misc-no-recursion,
           -misc-non-private-member-variables-in-classes,
           -modernize-concat-nested-namespaces,
           -modernize-type-traits,
           -modernize-use-constraints,
           -modernize-use-designated-initializers,
           -modernize-use-nodiscard,
           -modernize-use-ranges,
           -modernize-use-std-numbers,
           -modernize-use-trailing-return-type,
           -performance-enum-size,
           -portability-avoid-pragma-once,
           -readability-function-cognitive-complexity,
           -readability-function-size,
           -readability-identifier-length,
           -readability-magic-numbers,
           -readability-redundant-access-specifiers,
           -readability-redundant-parentheses,
           -readability-simplify-boolean-expr,
           -readability-uppercase-literal-suffix,
           -readability-use-concise-preprocessor-directives'

  CheckOptions:
    - key: hicpp-special-member-functions.AllowSoleDefaultDtor
      value: 1

  WarningsAsErrors: '*'

  #HeaderFilterRegex: '.*nlohmann.*'
  HeaderFilterRegex: '.*hpp$'
  ```

- The code is checked with the latest [Cppcheck](https://cppcheck.sourceforge.io) with all warnings enabled.

- The code is checked with the latest [Clang Static Analyzer](https://clang-analyzer.llvm.org) with 89 enabled rules.

- The code is checked with [Infer](https://fbinfer.com).

- The code is checked with [Codacy](https://app.codacy.com/gh/nlohmann/json/dashboard).

## Dynamic analysis

Requirement: Correctness

The library is checked for memory correctness and absence of undefined behavior.

- The test suite is executed with enabled [runtime assertions](https://json.nlohmann.me/features/assertions/) to check invariants and preconditions of functions to detect undefined behavior.
- The test suite is executed with [Valgrind](https://valgrind.org) (Memcheck) to detect memory leaks.
- The test suite is executed with [Sanitizers](https://github.com/google/sanitizers) (address sanitizer, undefined behavior sanitizer, integer overflow detection, nullability violations).

## Style check

Requirement: Common code style

A common code style is used throughout all code files of the library.

- The code is formatted with [Artistic Style](https://astyle.sourceforge.net) (astyle) against a style configuration that is also enforced in the CI.

  Astyle configuration (tools/astyle/.astylerc)

  ```
  # Configuration for Artistic Style
  # see https://astyle.sourceforge.net/astyle.html

  #######################
  # Brace Style Options #
  #######################

  # use Allman style for braces
  --style=allman

  ###############
  # Tab Options #
  ###############

  # indent using 4 spaces
  --indent=spaces=4

  #######################
  # Indentation Options #
  #######################

  # indent access modifiers one half indent
  --indent-modifiers

  # indent switch cases to the switch block
  --indent-switches

  # indent preprocessor blocks
  --indent-preproc-block

  # indent preprocessor defines
  --indent-preproc-define

  # indent C++ comments
  --indent-col1-comments

  ###################
  # Padding Options #
  ###################

  # insert space padding around operators
  --pad-oper

  # insert space between if/for/while... and the following parentheses
  --pad-header

  # attach the pointer to the variable type (left)
  --align-pointer=type

  # attach the reference to the variable type (left)
  --align-reference=type

  ######################
  # Formatting Options #
  ######################

  # add braces to unbraced one line conditional statements
  --add-braces

  # convert tabs to spaces
  --convert-tabs

  # closes whitespace between the ending angle brackets of template definitions
  --close-templates

  #################
  # Other Options #
  #################

  # do not create backup files
  --suffix=none

  # preserve the original file date
  --preserve-date

  # display only the files that have been formatted
  --formatted

  # for the linux (LF) line end style
  --lineend=linux
  ```

- The code style is checked with [cpplint](https://github.com/cpplint/cpplint) with 61 enabled rules.

## Simple integration

Requirement: Single header

The library can be used by adding a single header to a C++ project.

- An amalgamation script is used to check if the source code is exposed as a self-contained single-header file.
- The test suite is checked against the amalgamated source file as well as the individual source file.

Requirement: CMake as primary development tool

All library functions are exposed and usable by CMake.

- All library options are exposed as [CMake options](https://json.nlohmann.me/integration/cmake/) and tested.
- The library is tested against relevant CMake versions:
- CMake 3.5 (the earliest supported)
- CMake 3.31.6 (the latest 3.x release)
- CMake 4.0.0 (a very recent release)
