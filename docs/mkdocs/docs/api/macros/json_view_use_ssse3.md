# JSON_VIEW_USE_SSSE3

```cpp
#define JSON_VIEW_USE_SSSE3
```

When defined on x86-64, the parser of [`basic_json_document`](../basic_json_document/index.md)
(`<nlohmann/json_view.hpp>`) validates non-ASCII text in strings with SSSE3 without asking the CPU first.

By default, the parser checks once at run time whether the CPU has SSSE3 (all x86-64 CPUs since about 2011 have it)
and then validates non-ASCII text 16 bytes at a time, using the "lookup4" algorithm of
[simdjson](https://github.com/simdjson/simdjson); on CPUs without SSSE3, it validates one UTF-8 sequence at a time.
The vector check is compiled for SSSE3 with a function attribute (GCC 4.9 and later, Clang), so this needs no compiler
option. With MSVC, the check uses `__cpuid`. On AArch64, the vector check uses NEON and is always on.

Define the macro only together with a compiler option that enables SSSE3 (e.g. `-mssse3`, or `-march=` with a CPU that
has it), and only for programs that run on such CPUs. It saves the check of the CPU, which costs little. The same
input is accepted or rejected either way; only the speed of non-ASCII text differs.

!!! note "ABI compatibility"

    The macro selects between two definitions of the same inline functions. Whether it is defined is encoded in the
    [namespace](../../features/namespace.md) (tag `_vssse3`, on every architecture), resulting in distinct symbol
    names. Translation units compiled with and without it can therefore be linked into the same program without One
    Definition Rule (ODR) violations, but they cannot exchange instances of library types.

## Default definition

By default, `#!cpp JSON_VIEW_USE_SSSE3` is not defined.

```cpp
#undef JSON_VIEW_USE_SSSE3
```

## Examples

??? example

    With CMake, for a program that only runs on CPUs with SSSE3:

    ```cmake
    target_compile_definitions(your_target PRIVATE JSON_VIEW_USE_SSSE3)
    target_compile_options(your_target PRIVATE -mssse3)
    ```

## See also

- [JSON_VIEW_NO_SIMD](json_view_no_simd.md) - use only portable code in the view's parser
- [JSON_USE_SIMDUTF](json_use_simdutf.md) - validate UTF-8 with simdutf in `basic_json`'s parser

## Version history

- Added in version 3.13.0.
