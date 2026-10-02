# JSON_VIEW_NO_SIMD

```cpp
#define JSON_VIEW_NO_SIMD
```

When defined, the parser of [`basic_json_document`](../basic_json_document/index.md) (`<nlohmann/json_view.hpp>`)
uses only portable C++ to scan strings. By default, it scans long runs of string bytes 16 at a time with NEON on
AArch64 (with GCC and Clang) and SSE2 on x86-64, which are part of the baseline instruction sets of these
architectures, and validates non-ASCII text with NEON (or SSSE3, see
[`JSON_VIEW_USE_SSSE3`](json_view_use_ssse3.md)).

The same input is accepted or rejected either way, with the same values, and errors are reported the same way; only
the speed differs. The macro exists for platforms whose compilers lack the intrinsics headers, and to test the portable
code.

!!! warning "Define consistently"

    The macro selects between two definitions of the same inline functions. It must therefore be defined identically for
    **every** translation unit that includes `<nlohmann/json_view.hpp>`; prefer a compile definition on the target.

## Default definition

By default, `#!cpp JSON_VIEW_NO_SIMD` is not defined, and the vector code is used where available.

```cpp
#undef JSON_VIEW_NO_SIMD
```

## Examples

??? example

    The code below uses the portable string scanning of the view.

    ```cpp
    #define JSON_VIEW_NO_SIMD
    #include <nlohmann/json_view.hpp>

    ...
    ```

## See also

- [JSON_VIEW_USE_SSSE3](json_view_use_ssse3.md) - validate non-ASCII strings with SSSE3 on x86-64
- [json_view](../../features/json_view.md) - the zero-copy view

## Version history

- Added in version 3.13.0.
