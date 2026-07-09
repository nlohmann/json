# JSON_HAS_FILESYSTEM / JSON_HAS_EXPERIMENTAL_FILESYSTEM

```cpp
#define JSON_HAS_FILESYSTEM /* value */
#define JSON_HAS_EXPERIMENTAL_FILESYSTEM /* value */
```

When compiling with C++17, the library provides conversions from and to
[`std::filesystem::path`](https://en.cppreference.com/w/cpp/filesystem/path). As compiler support for filesystem is
limited, the library tries to detect whether
[`<filesystem>`/`std::filesystem`](https://en.cppreference.com/w/cpp/header/filesystem) (`JSON_HAS_FILESYSTEM`) or
[`<experimental/filesystem>`/`std::experimental::filesystem`](https://en.cppreference.com/w/cpp/header/experimental/filesystem)
(`JSON_HAS_EXPERIMENTAL_FILESYSTEM`) should be used. To override the built-in check, define `JSON_HAS_FILESYSTEM` or
`JSON_HAS_EXPERIMENTAL_FILESYSTEM` to `1`.

## Default definition

The default value is detected based on the preprocessor macros `#!cpp __cpp_lib_filesystem`,
`#!cpp __cpp_lib_experimental_filesystem`, `#!cpp __has_include(<filesystem>)`, or
`#!cpp __has_include(<experimental/filesystem>)`.

!!! info "Known compiler/stdlib exclusions"

    Even when the feature-test macro indicates filesystem support is available, the library disables it on the following broken toolchains:
    
    - **MinGW + GCC 8** — disabled entirely (broken `std::filesystem` implementation; [MinGW-w64 bug 737](https://sourceforge.net/p/mingw-w64/bugs/737/))
    - **GCC (non-Clang) < 8** — disabled (no filesystem support)
    - **Clang < 7** — disabled (no filesystem support)
    - **MSVC < 19.14** — disabled (no filesystem support)
    - **iOS < 13** — disabled (no filesystem support)
    - **macOS < Catalina (10.15)** — disabled (no filesystem support)
    
    If `JSON_HAS_FILESYSTEM` or `JSON_HAS_EXPERIMENTAL_FILESYSTEM` is `0` despite `__cpp_lib_filesystem` being defined, one
    of the exclusions above likely applies to your toolchain.

## Notes

- Note that older compilers or older versions of libstdc++ also require the library `stdc++fs` to be linked to for
  filesystem support.
- Both macros are undefined outside the library.

## Examples

??? example

    The code below forces the library to use the header `<experimental/filesystem>`.

    ```cpp
    #define JSON_HAS_EXPERIMENTAL_FILESYSTEM 1
    #include <nlohmann/json.hpp>

    ...
    ```

## Version history

- Added in version 3.10.5.
