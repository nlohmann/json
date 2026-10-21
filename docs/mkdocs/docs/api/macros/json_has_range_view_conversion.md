# JSON_HAS_RANGE_VIEW_CONVERSION

```cpp
#define JSON_HAS_RANGE_VIEW_CONVERSION /* value */
```

This macro indicates whether a JSON array can be constructed directly from a C++20 range view (`std::ranges::view`),
such as the result of `std::views::filter` or `std::views::transform`. Possible values are `1` when supported or `0`
when unsupported.

## Default definition

The default value is `1` if [`JSON_HAS_RANGES`](json_has_ranges.md) is `1` and the compiler is not MinGW (that is,
`#!cpp __MINGW32__` is not defined), and `0` otherwise.

When the macro is not defined, the library will define it to its default value.

!!! info "Known compiler/stdlib exclusions"

    - **MinGW** -- disabled, because its `std::ranges` support is incomplete ([issue #4916](https://github.com/nlohmann/json/issues/4916)).
    - All toolchains for which [`JSON_HAS_RANGES`](json_has_ranges.md#default-definition) is disabled.

## Examples

??? example

    The code below forces the library to disable the conversion from range views:

    ```cpp
    #define JSON_HAS_RANGE_VIEW_CONVERSION 0
    #include <nlohmann/json.hpp>

    ...
    ```

## See also

- [JSON_HAS_RANGES](json_has_ranges.md) - control `std::ranges` support
- [Constructing from a C++20 range view](../../features/conversions.md#putting-values-in) - usage of the feature

## Version history

- Added in version 3.13.0.
