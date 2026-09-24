# JSON_HAS_THREE_WAY_COMPARISON

```cpp
#define JSON_HAS_THREE_WAY_COMPARISON /* value */
```

This macro indicates whether the compiler and standard library support 3-way comparison.
Possible values are `1` when supported or `0` when unsupported.

## Default definition

The default value is detected based on the preprocessor macros `#!cpp __cpp_impl_three_way_comparison`
and `#!cpp __cpp_lib_three_way_comparison`.

When the macro is not defined, the library will define it to its default value.

## Examples

??? example

    The code below forces the library to use 3-way comparison:

    ```cpp
    #define JSON_HAS_THREE_WAY_COMPARISON 1
    #include <nlohmann/json.hpp>

    ...
    ```

## Version history

- Added in version 3.11.0.
