# JSON_USE_IMPLICIT_CONVERSIONS

```cpp
#define JSON_USE_IMPLICIT_CONVERSIONS /* value */
```

When defined to `0`, implicit conversions are switched off. By default, implicit conversions are switched on. The
value directly affects [`operator ValueType`](../basic_json/operator_ValueType.md) and the
[converting constructor](../basic_json/basic_json.md) from a `basic_json` specialization with a different string
type (overload 4).

## Default definition

By default, implicit conversions are enabled.

```cpp
#define JSON_USE_IMPLICIT_CONVERSIONS 1
```

## Notes

!!! info "Future behavior change"

    Implicit conversions will be switched off by default in the next major release of the library.

    You can prepare existing code by already defining `JSON_USE_IMPLICIT_CONVERSIONS` to `0` and replace any implicit
    conversions with calls to [`get`](../basic_json/get.md).

    See the [migration guide](../../integration/migration_guide.md#replace-implicit-conversions) for how to update existing code.

!!! tip "Automatic migration"

    The community-maintained clang-tidy check `modernize-nlohmann-json-explicit-conversions` rewrites implicit
    conversions into explicit calls to [`get`](../basic_json/get.md); for example, `#!cpp int i = j;` becomes
    `#!cpp int i = j.get<int>();`. The check is not part of clang-tidy itself, and it does not catch every case (for
    example, constructing a `std::optional` from a JSON value), so review the result. See
    [discussion #4610](https://github.com/nlohmann/json/discussions/4610) for how to build and use it.

!!! hint "CMake option"

    Implicit conversions can also be controlled with the CMake option
    [`JSON_ImplicitConversions`](../../integration/cmake.md#json_implicitconversions)
    (`ON` by default) which defines `JSON_USE_IMPLICIT_CONVERSIONS` accordingly.

## Examples

??? example "Example: implicit conversion"

    This is an example for an implicit conversion:

    ```cpp
    json j = "Hello, world!";
    std::string s = j;
    ```

    When `JSON_USE_IMPLICIT_CONVERSIONS` is defined to `0`, the code above does no longer compile. Instead, it must be
    written like this:

    ```cpp
    json j = "Hello, world!";
    auto s = j.get<std::string>();
    ```

??? example "Example: conversion between `basic_json` specializations"

    A `basic_json` specialization with a different string type is also no longer converted implicitly when
    `JSON_USE_IMPLICIT_CONVERSIONS` is defined to `0`:

    ```cpp
    using wjson = nlohmann::basic_json<std::map, std::vector, std::wstring>;

    void load(const nlohmann::json& j);

    wjson wj = /* ... */;
    load(wj);                            // error: no implicit conversion
    load(nlohmann::json(wj));            // OK: explicit conversion
    load(wj.get<nlohmann::json>());      // OK: explicit conversion
    ```

    Specializations that share the same string type, such as `json` and `ordered_json`, remain implicitly
    convertible.

## See also

- [**operator ValueType**](../basic_json/operator_ValueType.md) - get a value (implicit)
- [**get**](../basic_json/get.md) - get a value (explicit)
- [:simple-cmake: JSON_ImplicitConversions](../../integration/cmake.md#json_implicitconversions) - CMake option to control the macro

## Version history

- Added in version 3.9.0.
- Also affects the conversion between `basic_json` specializations with different string types since version 3.13.0.
