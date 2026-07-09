# JSON_HAS_RANGES

```cpp
#define JSON_HAS_RANGES /* value */
```

This macro indicates whether the standard library has any support for ranges. Implies support for concepts.
Possible values are `1` when supported or `0` when unsupported.

## Default definition

The default value is detected based on the preprocessor macro `#!cpp __cpp_lib_ranges`.

When the macro is not defined, the library will define it to its default value.

!!! info "Known compiler/stdlib exclusions"

    Even when the feature-test macro `__cpp_lib_ranges` indicates ranges support is available, the library disables it on
    the following incomplete or broken toolchains:
    
    - **GCC 11.1.0** — disabled (the shipped `<ranges>` header has a syntax error; [issue #4440](https://github.com/nlohmann/json/issues/4440))
    - **libstdc++ < 11** — disabled (incomplete C++20 ranges support; [issue #4440](https://github.com/nlohmann/json/issues/4440))
    - **Clang < 16 with libstdc++** — disabled (incomplete ranges support; [issue #4440](https://github.com/nlohmann/json/issues/4440))
    - **libc++ < 160000** — disabled (incomplete C++20 ranges support; [issue #4440](https://github.com/nlohmann/json/issues/4440))
    - **nvcc (CUDA) 12.0.x and 12.1.x** — disabled (the `enable_borrowed_range` variable-template syntax triggers a parse error
      under these two toolkit versions; fixed in CUDA 12.2; [issue #3907](https://github.com/nlohmann/json/issues/3907))
    
    If `JSON_HAS_RANGES` is `0` despite `__cpp_lib_ranges` being defined, one of the exclusions above likely applies to your toolchain.

## Examples

??? example

    The code below forces the library to enable support for ranges:

    ```cpp
    #define JSON_HAS_RANGES 1
    #include <nlohmann/json.hpp>

    ...
    ```

## Version history

- Added in version 3.11.0.
