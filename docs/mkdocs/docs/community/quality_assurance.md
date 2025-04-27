# Quality assurance

Ensuring quality is paramount for this project, particularly because [numerous other projects](../home/customers.md)
depend on it. Each commit to the library undergoes rigorous checks against the following requirements, and any
violations will result in a failed build.

## C++ language compliance and compiler compatibility

!!! success "Requirement: Compiler support"

    Any compiler with complete C++11 support can compile the library without warnings.

- [x] The library is compiled with 50+ different C++ compilers with different operating systems and platforms,
  including the oldest versions known to compile the library.

    ??? abstract "Compilers used in continuous integration"
      
        | Compiler                                     | Architecture | Operating System         | CI        |
        |----------------------------------------------|--------------|--------------------------|-----------|
        | AppleClang 14.0.0.14000029; Xcode 14.1       | x86_64       | macOS 13.7.2 (Ventura)   | GitHub    |
        | AppleClang 14.0.0.14000029; Xcode 14.2       | x86_64       | macOS 13.7.2 (Ventura)   | GitHub    |
        | AppleClang 14.0.3.14030022; Xcode 14.3.1     | x86_64       | macOS 13.7.2 (Ventura)   | GitHub    |
        | AppleClang 15.0.0.15000040; Xcode 15.0.1     | x86_64       | macOS 13.7.2 (Ventura)   | GitHub    |
        | AppleClang 15.0.0.15000100; Xcode 15.1       | x86_64       | macOS 13.7.2 (Ventura)   | GitHub    |
        | AppleClang 15.0.0.15000100; Xcode 15.2       | x86_64       | macOS 13.7.2 (Ventura)   | GitHub    |
        | AppleClang 15.0.0.15000309; Xcode 15.3       | arm64        | macOS 14.7.2 (Sonoma)    | GitHub    |
        | AppleClang 15.0.0.15000309; Xcode 15.4       | arm64        | macOS 14.7.2 (Sonoma)    | GitHub    |
        | AppleClang 16.0.0.16000026; Xcode 16         | arm64        | macOS 15.2 (Sequoia)     | GitHub    |
        | AppleClang 16.0.0.16000026; Xcode 16.1       | arm64        | macOS 15.2 (Sequoia)     | GitHub    |
        | AppleClang 16.0.0.16000026; Xcode 16.2       | arm64        | macOS 15.2 (Sequoia)     | GitHub    |
        | Clang 3.5.2                                  | x86_64       | Ubuntu 22.04.1 LTS       | GitHub    |
        | Clang 3.6.2                                  | x86_64       | Ubuntu 22.04.1 LTS       | GitHub    |
        | Clang 3.7.1                                  | x86_64       | Ubuntu 22.04.1 LTS       | GitHub    |
        | Clang 3.8.1                                  | x86_64       | Ubuntu 22.04.1 LTS       | GitHub    |
        | Clang 3.9.1                                  | x86_64       | Ubuntu 22.04.1 LTS       | GitHub    |
        | Clang 4.0.1                                  | x86_64       | Ubuntu 22.04.1 LTS       | GitHub    |
        | Clang 5.0.2                                  | x86_64       | Ubuntu 22.04.1 LTS       | GitHub    |
        | Clang 6.0.1                                  | x86_64       | Ubuntu 22.04.1 LTS       | GitHub    |
        | Clang 7.1.0                                  | x86_64       | Ubuntu 22.04.1 LTS       | GitHub    |
        | Clang 8.0.1                                  | x86_64       | Ubuntu 22.04.1 LTS       | GitHub    |
        | Clang 9.0.1                                  | x86_64       | Ubuntu 22.04.1 LTS       | GitHub    |
        | Clang 10.0.1                                 | x86_64       | Ubuntu 22.04.1 LTS       | GitHub    |
        | Clang 11.0.0 with GNU-like command-line      | x86_64       | Windows 10 (Build 17763) | GitHub    |
        | Clang 11.1.0                                 | x86_64       | Ubuntu 22.04.1 LTS       | GitHub    |
        | Clang 12.0.0 with GNU-like command-line      | x86_64       | Windows 10 (Build 17763) | GitHub    |
        | Clang 12.0.0 with MSVC-like command-line     | x86_64       | Windows 10 (Build 17763) | GitHub    |
        | Clang 12.0.1                                 | x86_64       | Ubuntu 22.04.1 LTS       | GitHub    |
        | Clang 13.0.0 with GNU-like command-line      | x86_64       | Windows 10 (Build 17763) | GitHub    |
        | Clang 13.0.1                                 | x86_64       | Ubuntu 22.04.1 LTS       | GitHub    |
        | Clang 14.0.0 with GNU-like command-line      | x86_64       | Windows 10 (Build 17763) | GitHub    |
        | Clang 14.0.6                                 | x86_64       | Ubuntu 22.04.1 LTS       | GitHub    |
        | Clang 15.0.0 with GNU-like command-line      | x86_64       | Windows 10 (Build 17763) | GitHub    |
        | Clang 15.0.7                                 | x86_64       | Ubuntu 22.04.1 LTS       | GitHub    |
        | Clang 16.0.6                                 | x86_64       | Ubuntu 22.04.1 LTS       | GitHub    |
        | Clang 17.0.6                                 | x86_64       | Ubuntu 22.04.1 LTS       | GitHub    |
        | Clang 18.1.8                                 | x86_64       | Ubuntu 22.04.1 LTS       | GitHub    |
        | Clang 19.1.7                                 | x86_64       | Ubuntu 22.04.1 LTS       | GitHub    |
        | Clang 20.1.1                                 | x86_64       | Ubuntu 22.04.1 LTS       | GitHub    |
        | Clang 21.0.0                                 | x86_64       | Ubuntu 22.04.1 LTS       | GitHub    |
        | Emscripten 4.0.6                             | x86_64       | Ubuntu 22.04.1 LTS       | GitHub    |
        | GNU 4.8.5                                    | x86_64       | Ubuntu 22.04.1 LTS       | GitHub    |
        | GNU 4.9.3                                    | x86_64       | Ubuntu 22.04.1 LTS       | GitHub    |
        | GNU 5.5.0                                    | x86_64       | Ubuntu 22.04.1 LTS       | GitHub    |
        | GNU 6.4.0                                    | x86_64       | Ubuntu 22.04.1 LTS       | GitHub    |
        | GNU 7.5.0                                    | x86_64       | Ubuntu 22.04.1 LTS       | GitHub    |
        | GNU 8.5.0                                    | x86_64       | Ubuntu 22.04.1 LTS       | GitHub    |
        | GNU 9.3.0                                    | x86_64       | Ubuntu 22.04.1 LTS       | GitHub    |
        | GNU 9.4.0                                    | x86_64       | Ubuntu 22.04.1 LTS       | GitHub    |
        | GNU 9.5.0                                    | x86_64       | Ubuntu 22.04.1 LTS       | GitHub    |
        | GNU 10.5.0                                   | x86_64       | Ubuntu 22.04.1 LTS       | GitHub    |
        | GNU 11.4.0                                   | x86_64       | Ubuntu 22.04.1 LTS       | GitHub    |
        | GNU 11.5.0                                   | x86_64       | Ubuntu 22.04.1 LTS       | GitHub    |
        | GNU 12.2.0 (MinGW-W64 i686-ucrt-posix-dwarf) | x86_64       | Windows 10 (Build 17763) | GitHub    |
        | GNU 12.2.0 (MinGW-W64 x86_64-ucrt-posix-seh) | x86_64       | Windows 10 (Build 17763) | GitHub    |
        | GNU 12.4.0                                   | x86_64       | Ubuntu 22.04.1 LTS       | GitHub    |
        | GNU 13.3.0                                   | x86_64       | Ubuntu 22.04.1 LTS       | GitHub    |
        | GNU 14.2.0                                   | x86_64       | Ubuntu 22.04.1 LTS       | GitHub    |
        | GNU 14.2.0                                   | arm64        | Linux 6.1.100            | Cirrus CI |
        | GNU 15.1.0                                   | x86_64       | Ubuntu 22.04.1 LTS       | GitHub    |
        | icpc (ICC) 2021.5.0 20211109                 | x86_64       | Ubuntu 20.04.3 LTS       | GitHub    |
        | MSVC 19.0.24241.7                            | x86          | Windows 8.1              | AppVeyor  |
        | MSVC 19.16.27035.0                           | x86          | Windows-10 (Build 14393) | AppVeyor  |
        | MSVC 19.29.30157.0                           | x86          | Windows 10 (Build 17763) | GitHub    |
        | MSVC 19.29.30157.0                           | x86_64       | Windows 10 (Build 17763) | GitHub    |
        | MSVC 19.29.30157.0                           | x86          | Windows-10 (Build 17763) | AppVeyor  |
        | MSVC 19.42.34435.0                           | x86          | Windows 10 (Build 20348) | GitHub    |
        | MSVC 19.42.34435.0                           | x86_64       | Windows 10 (Build 20348) | GitHub    |

- [x] The library is compiled with all C++ language revisions (C++11, C++14, C++17, C++20, C++23, and C++26) to detect
  and fix language deprecations early.
- [x] The library is checked for compiler warnings:
  - On Clang, `-Weverything` is used with 7 exceptions.

    ??? abstract "Clang warnings"

        ```cmake
        --8<-- "../../../cmake/clang_flags.cmake"
        ```

  - On GCC, 300+ warnings are enabled with 8 exceptions.

    ??? abstract "GCC warnings"

        ```cmake
        --8<-- "../../../cmake/gcc_flags.cmake"
        ```

## C++ standard library compliance

!!! success "Requirement: No prerequisites"

    The library has no prerequisites other than the Standard Template Library (STL).

- [x] The library is compiled and tested with both [libc++](https://libcxx.llvm.org) and
  [libstdc++](https://gcc.gnu.org/onlinedocs/libstdc++/) to detect subtle differences or incompatibilities.
- [x] The code checked with [Include What You Use (IWYU)](https://include-what-you-use.org) that all required standard
  headers are included.
- [x] On Windows, the library is compiled with `<Windows.h>` being included to detect and avoid common bugs.
- [x] The library is compiled with exceptions disabled to support alternative means of error handling.

## Stable public API

!!! success "Requirement: Stable public API"

    Any change to the library does not break the public API.

- [x] All public API functions are tested with a variety of arguments.
- [x] The library is compiled and tested with different template arguments for number, string, array, and object types.
- [x] Unit tests cover all lines of the code base.
- [x] Every exception of the library is thrown in the test suite, and the error messages and exception ids are checked.

!!! success "Requirement: Complete documentation"

    The public API is extensively documented.

- [x] Every public API function has a dedicated page in the
  [API reference documentation](https://json.nlohmann.me/api/basic_json/) with a self-contained code example.
- [x] All examples in the documentation are tested, and changes in their output are treated as an error.

## Robust input processing

!!! success "Requirement: Standards compliance"

    The library is compliant to JSON as defined in [RFC 8259](https://datatracker.ietf.org/doc/html/rfc8259).

- [x] The lexer is tested with all valid Unicode code points and all prefixes of all invalid Unicode code points.
- [x] The parser is tested against extensive correctness suites for JSON compliance.
- [x] In addition, the library is continuously fuzz-tested at [OSS-Fuzz](https://google.github.io/oss-fuzz/) where the
  library is checked against billions of inputs.

## Static analysis

!!! success "Requirement: State-of-the-art code analysis"

    The code is checked with state-of-the-art static code analysis tools.

- [x] The code is checked with the latest [Clang-Tidy](https://clang.llvm.org/extra/clang-tidy/).

    ??? abstract "Clang-Tidy configuration (.clang-tidy)"

        ```ini
        --8<-- "../../../.clang-tidy"
        ```

- [x] The code is checked with the latest [Cppcheck](https://cppcheck.sourceforge.io) with all warnings enabled.
- [x] The code is checked with the latest [Clang Static Analyzer](https://clang-analyzer.llvm.org) with 89 enabled
  rules.
- [x] The code is checked with [Infer](https://fbinfer.com).
- [x] The code is checked with [Codacy](https://app.codacy.com/gh/nlohmann/json/dashboard).

## Dynamic analysis

!!! success "Requirement: Correctness"

    The library is checked for memory correctness and absence of undefined behavior.

- [x] The test suite is executed with enabled [runtime assertions](https://json.nlohmann.me/features/assertions/) to
  check invariants and preconditions of functions to detect undefined behavior.
- [x] The test suite is executed with [Valgrind](https://valgrind.org) (Memcheck) to detect memory leaks.
- [x] The test suite is executed with [Sanitizers](https://github.com/google/sanitizers) (address sanitizer, undefined
  behavior sanitizer, integer overflow detection, nullability violations).

## Style check

!!! success "Requirement: Common code style"

    A common code style is used throughout all code files of the library.

- [x] The code is formatted with [Artistic Style](https://astyle.sourceforge.net) (astyle) against a style configuration
  that is also enforced in the CI.

    ??? abstract "Astyle configuration (tools/astyle/.astylerc)"
      
        ```ini
        --8<-- "../../../tools/astyle/.astylerc"
        ```

- [x] The code style is checked with [cpplint](https://github.com/cpplint/cpplint) with 61 enabled rules.

## Simple integration

!!! success "Requirement: Single header"

    The library can be used by adding a single header to a C++ project.

- [x] An amalgamation script is used to check if the source code is exposed as a self-contained single-header file.
- [x] The test suite is checked against the amalgamated source file as well as the individual source file.

!!! success "Requirement: CMake as primary development tool"

    All library functions are exposed and usable by CMake.

- [x] All library options are exposed as [CMake options](https://json.nlohmann.me/integration/cmake/) and tested.
- [x] The library is tested against relevant CMake versions:
  - CMake 3.5 (the earliest supported)
  - CMake 3.31.6 (the latest 3.x release)
  - CMake 4.0.0 (a very recent release)
