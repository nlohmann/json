# JSON_HAS_REFLECTION

```cpp
#define JSON_HAS_REFLECTION /* value */
```

This macro indicates whether the compiler supports
[static reflection](https://en.wikipedia.org/wiki/Reflection_(C%2B%2B)) together with annotations, introduced in C++26,
which the experimental reflection-based [`serialize`](../basic_json/serialize.md) and
[`deserialize`](../basic_json/deserialize.md) functions require. Possible values are `1` when supported or `0` when
unsupported.

## Default definition

The default value is detected based on the preprocessor macro `#!cpp __cpp_impl_reflection`.

When the macro is not defined, the library will define it to its default value.

## Notes

!!! info "Enabled functionality"

    When this macro evaluates to `1`, the library provides:

    - [`basic_json::serialize`](../basic_json/serialize.md) and [`basic_json::deserialize`](../basic_json/deserialize.md)
    - the annotations `nlohmann::transient`, `nlohmann::flatten`, `nlohmann::reflectable`, and `nlohmann::rename`
    - the [`deserialization_error`](../basic_json/deserialization_error.md) exception

!!! info "Compiler support"

    As of the time of writing, GCC 16 is the only compiler that provides the required support, and it must be invoked
    with the `-freflection` flag. On every other toolchain the macro evaluates to `0` and the functionality above is
    absent; the [`NLOHMANN_DEFINE_TYPE_*`](nlohmann_define_type_intrusive.md) macros remain the way to convert user
    types.

!!! info "Related macro: `JSON_SERDE_ALLOW_PRIVATE`"

    `#!cpp #define JSON_SERDE_ALLOW_PRIVATE /* value */` controls whether the reflection-based serde API may reach
    **private and protected** data members without the type being annotated
    [`reflectable`](../basic_json/serialize.md#notes). Possible values are `1` (allow) or `0` (require the annotation).
    The default is `0`; when the macro is not defined, the library defines it to that default.

!!! warning "Encapsulation"

    Setting `JSON_SERDE_ALLOW_PRIVATE` to `1` lets the serializer read and write the private state of **every** type it
    serializes, defeating their encapsulation. Prefer annotating individual types with
    `#!cpp [[=nlohmann::reflectable]]` unless you deliberately want the global behavior.

## Examples

??? example

    The code below forces the library to disable the reflection-based serde API, even if the compiler would otherwise
    support it:

    ```cpp
    #define JSON_HAS_REFLECTION 0
    #include <nlohmann/json.hpp>

    ...
    ```

## See also

- [`serialize`](../basic_json/serialize.md) - map an object to a JSON value via reflection
- [`deserialize`](../basic_json/deserialize.md) - map a JSON value into an object via reflection
- [`deserialization_error`](../basic_json/deserialization_error.md) - the exception thrown on a failed reflection-based conversion
- [Supported Macros](../../features/macros.md) - guide to all supported macros
- [Arbitrary Type Conversions](../../features/arbitrary_types.md) - overview of converting user types to and from JSON

## Version history

- Added in version 3.13.0.
