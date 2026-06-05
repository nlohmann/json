# JSON_HAS_CPP_11, JSON_HAS_CPP_14, JSON_HAS_CPP_17, JSON_HAS_CPP_20

```cpp
#define JSON_HAS_CPP_11
#define JSON_HAS_CPP_14
#define JSON_HAS_CPP_17
#define JSON_HAS_CPP_20
```

The library targets C++11, but also supports some features introduced in later C++ versions (e.g., `std::string_view`
support for C++17). For these new features, the library implements some preprocessor checks to determine the C++
standard. By defining any of these symbols, the internal check is overridden and the provided C++ version is
unconditionally assumed. This can be helpful for compilers that only implement parts of the standard and would be
detected incorrectly.

## Default definition

The default value is detected based on preprocessor macros such as `#!cpp __cplusplus`, `#!cpp _HAS_CXX17`, or
`#!cpp _MSVC_LANG`.

## Notes

- `#!cpp JSON_HAS_CPP_11` is always defined.
- All macros are undefined outside the library.

## Examples

??? example

    The code below forces the library to use the C++14 standard:

    ```cpp
    #define JSON_HAS_CPP_14 1
    #include <nlohmann/json.hpp>

    ...
    ```

## Version history

- Added in version 3.10.5.
