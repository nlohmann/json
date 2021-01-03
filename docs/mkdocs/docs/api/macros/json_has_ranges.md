# JSON_HAS_RANGES

```cpp
#define JSON_HAS_RANGES /* value */
```

This macro indicates whether the standard library has any support for ranges. Implies support for concepts.
Possible values are `1` when supported or `0` when unsupported.

## Default definition

The default value is detected based on the preprocessor macro `#!cpp __cpp_lib_ranges`.

When the macro is not defined, the library will define it to its default value.

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
