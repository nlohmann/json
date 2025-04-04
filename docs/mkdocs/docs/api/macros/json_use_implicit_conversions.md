# JSON_USE_IMPLICIT_CONVERSIONS

```cpp
#define JSON_USE_IMPLICIT_CONVERSIONS /* value */
```

When defined to `0`, implicit conversions are switched off. By default, implicit conversions are switched on. The
value directly affects [`operator ValueType`](../basic_json/operator_ValueType.md).

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

!!! hint "CMake option"

    Implicit conversions can also be controlled with the CMake option
    [`JSON_ImplicitConversions`](../../integration/cmake.md#json_implicitconversions)
    (`ON` by default) which defines `JSON_USE_IMPLICIT_CONVERSIONS` accordingly.

## Examples

??? example

    This is an example for an implicit conversion:

    ```cpp
    json j = "Hello, world!";
    std::string s = j;
    ```

    When `JSON_USE_IMPLICIT_CONVERSIONS` is defined to `0`, the code above does no longer compile. Instead, it must be
    written like this:

    ```cpp
    json j = "Hello, world!";
    auto s = j.template get<std::string>();
    ```

## See also

- [**operator ValueType**](../basic_json/operator_ValueType.md) - get a value (implicit)
- [**get**](../basic_json/get.md) - get a value (explicit)
- [:simple-cmake: JSON_ImplicitConversions](../../integration/cmake.md#json_implicitconversions) - CMake option to control the macro

## Version history

- Added in version 3.9.0.
