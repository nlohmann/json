# JSON_VIEW_USE_SSSE3

```cpp
#define JSON_VIEW_USE_SSSE3
```

When defined on x86-64, the parser of [`basic_json_document`](../basic_json_document/index.md)
(`<nlohmann/json_view.hpp>`) validates non-ASCII text in strings with SSSE3, 16 bytes at a time, using the "lookup4"
algorithm of [simdjson](https://github.com/simdjson/simdjson). Without it, non-ASCII text is validated one UTF-8
sequence at a time on x86-64; on AArch64, the vector check uses NEON and is always on.

SSSE3 is not part of the x86-64 baseline, so the code must be compiled for it: define the macro only together with a
compiler option that enables SSSE3 (e.g. `-mssse3`, or `-march=` with a CPU that has it), and only for programs that
run on such CPUs. The same input is accepted or rejected either way; only the speed of non-ASCII text differs.

!!! warning "Define consistently"

    The macro selects between two definitions of the same inline functions. It must therefore be defined identically,
    with the same compiler options, for **every** translation unit that includes `<nlohmann/json_view.hpp>`; mixing
    translation units that define it with ones that do not is an ODR violation. Prefer a compile definition on the
    target.

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
