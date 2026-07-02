# JSON_HAS_STD_FORMAT

```cpp
#define JSON_HAS_STD_FORMAT /* value */
```

This macro indicates whether the standard library has support for `std::format`/`std::formatter` (that
is, the `<format>` header). Possible values are `1` when supported or `0` when unsupported.

## Default definition

The default value is detected based on the preprocessor macros `#!cpp JSON_HAS_CPP_20` and
`#!cpp __cpp_lib_format`.

When the macro is not defined, the library will define it to its default value.

## Notes

!!! info "Enabled functionality"

    When this macro evaluates to `1`, the library provides a
    [`std::formatter<basic_json>`](../basic_json/std_formatter.md) specialization so JSON values can be
    used directly with `std::format`.

## Examples

??? example

    The code below forces the library to disable support for `std::format`, even if the standard library
    would otherwise support it:

    ```cpp
    #define JSON_HAS_STD_FORMAT 0
    #include <nlohmann/json.hpp>

    ...
    ```

## Version history

- Added in version 3.12.x.
