# JSON_DISABLE_TUPLE_REFERENCE_CONVERSION

```cpp
#define JSON_DISABLE_TUPLE_REFERENCE_CONVERSION /* value */
```

When defined to `1`, a `basic_json` value can no longer be constructed from a one-element `std::tuple` whose element is
a reference to that `basic_json` type, such as `std::tuple<json&>`, `std::tuple<const json&>`, or `std::tuple<json&&>`.
These are the tuples created by `std::forward_as_tuple(j)`.

## Default definition

The default value is `0` (disabled — existing behavior is preserved).

```cpp
#define JSON_DISABLE_TUPLE_REFERENCE_CONVERSION 0
```

## Notes

!!! note "Background"

    By default, `basic_json` can be constructed from any `std::tuple` whose elements can be converted to JSON; the result
    is an array. This includes `std::tuple<json&>`, which becomes a one-element array.

    `std::tuple` only converts another tuple element by element if its element type cannot be constructed from the whole
    source tuple. Because `json` *can* be constructed from `std::tuple<json&>`, `std::tuple` instead converts the whole
    tuple into a single `json` value. This has two surprising effects:

    ```cpp
    json j = true;

    // rejected by some standard libraries (e.g., libc++); with others, the
    // reference binds to a temporary that is destroyed right away
    std::tuple<const json&> t1(std::forward_as_tuple(j));

    // compiles, but std::get<0>(t2) is [true], not true
    std::tuple<json> t2(std::forward_as_tuple(j));
    ```

    Enabling this macro removes the conversion, so both tuples are converted element by element: `std::get<0>(t1)`
    refers to `j`, and `std::get<0>(t2)` is a copy of `j` (see [#2226](https://github.com/nlohmann/json/issues/2226)).

!!! warning "Opt-in only"

    This macro must be defined **before** including `<nlohmann/json.hpp>`. Defining it after the include has no effect.

!!! note "Affected conversions"

    Only one-element tuples holding a reference to the **same** `basic_json` type are affected. Constructing a JSON value
    from them no longer compiles:

    ```cpp
    json j = true;
    json a = std::forward_as_tuple(j);  // error with the macro enabled
    json b = json::array({j});          // use this instead: [true]
    ```

    Tuples holding a JSON value (`std::make_tuple(j)`), tuples with more than one element, and tuples holding references
    to other types (including other `basic_json` specializations) are converted to arrays as before.

!!! hint "CMake option"

    This behavior can also be controlled with the CMake option
    [`JSON_DisableTupleReferenceConversion`](../../integration/cmake.md#json_disabletuplereferenceconversion)
    (`OFF` by default) which defines `JSON_DISABLE_TUPLE_REFERENCE_CONVERSION` accordingly.

## Examples

??? example "Example: default behavior (macro not defined)"

    ```cpp
    #include <nlohmann/json.hpp>

    using json = nlohmann::json;

    int main()
    {
        json j = true;

        std::tuple<json> t(std::forward_as_tuple(j));
        // std::get<0>(t) is [true] -- the whole tuple was converted
    }
    ```

??? example "Example: conversion disabled (macro defined to 1)"

    ```cpp
    #define JSON_DISABLE_TUPLE_REFERENCE_CONVERSION 1
    #include <nlohmann/json.hpp>

    using json = nlohmann::json;

    int main()
    {
        json j = true;

        std::tuple<json> t(std::forward_as_tuple(j));
        // std::get<0>(t) is true -- a copy of j

        std::tuple<const json&> r(std::forward_as_tuple(j));
        // std::get<0>(r) refers to j
    }
    ```

## See also

- [**basic_json(CompatibleType&&)**](../basic_json/basic_json.md) - the affected constructor
- [:simple-cmake: JSON_DisableTupleReferenceConversion](../../integration/cmake.md#json_disabletuplereferenceconversion) -
  CMake option to control the macro

## Version history

- Added in version 3.13.0.
