# JSON_USE_SIMDUTF

```cpp
#define JSON_USE_SIMDUTF
```

When defined, the parser validates the UTF-8 content of JSON strings that come from a **contiguous byte input**
(`std::string`, `std::vector<char>`/`<std::uint8_t>`, string literals, `const char*` ranges, …) using the
[simdutf](https://github.com/simdutf/simdutf) library instead of the built-in scalar validator. On text with many
non-ASCII characters (e.g. CJK or emoji) this can validate several times faster.

This is an **opt-in external dependency**. The library itself remains header-only and its behavior is unchanged: the
same input is accepted or rejected either way, and every parse error is reported at the same position with the same
message (simdutf is only used to fast-path *valid* runs; anything it flags falls back to the scalar path so the exact
diagnostic is preserved). Streaming inputs (files, `std::istream`, wide strings, user-defined adapters) always use the
scalar path.

When `JSON_USE_SIMDUTF` is defined you must make the `simdutf.h` header available on the include path and link the
simdutf library. When it is not defined, no simdutf header is included and there is no dependency.

!!! warning "Define consistently"

    The macro selects between two definitions of the same inline validation function. It must therefore be defined
    identically for **every** translation unit that includes the library; mixing translation units that define it with
    ones that do not is an ODR violation. Prefer setting it as a compile definition on the target rather than with
    `#!cpp #define` in individual source files.

## Default definition

By default, `#!cpp JSON_USE_SIMDUTF` is not defined and the portable C++11 scalar validator is used.

```cpp
#undef JSON_USE_SIMDUTF
```

## Examples

??? example

    The code below enables the simdutf backend for UTF-8 validation.

    ```cpp
    #define JSON_USE_SIMDUTF 1
    #include <simdutf.h>
    #include <nlohmann/json.hpp>

    ...
    ```

    The project must also link against simdutf, e.g. with CMake:

    ```cmake
    target_compile_definitions(your_target PRIVATE JSON_USE_SIMDUTF)
    target_link_libraries(your_target PRIVATE simdutf::simdutf)
    ```

## Version history

- Added in version 3.12.1.
