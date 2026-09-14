# Ignored Clang warnings:
# -Wno-c++98-compat               The library targets C++11.
# -Wno-c++98-compat-pedantic      The library targets C++11.
# -Wno-deprecated-declarations    The library contains annotations for deprecated functions.
# -Wno-extra-semi-stmt            The library uses assert which triggers this warning.
# -Wno-padded                     We do not care about padding warnings.
# -Wno-covered-switch-default     All switches list all cases and a default case.
# -Wno-c2y-extensions             Clang 22.1 diagnoses __COUNTER__ as a C2y extension, also in
#                                 C++ mode. The library does not use __COUNTER__; the warnings
#                                 all come from vendored Doctest (SECTION/TEST_CASE macros).
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
    -Wno-c2y-extensions
    -Wno-unsafe-buffer-usage
)
