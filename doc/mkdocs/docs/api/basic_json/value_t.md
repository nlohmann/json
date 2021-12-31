# <small>nlohmann::basic_json::</small>value_t

```cpp
enum class value_t : std::uint8_t {
    null,
    object,
    array,
    string,
    boolean,
    number_integer,
    number_unsigned,
    number_float,
    binary,
    discarded
};
```

This enumeration collects the different JSON types. It is internally used to distinguish the stored values, and the
functions [`is_null`](is_null.md), [`is_object`](is_object.md), [`is_array`](is_array.md), [`is_string`](is_string.md),
[`is_boolean`](is_boolean.md), [`is_number`](is_number.md) (with [`is_number_integer`](is_number_integer.md),
[`is_number_unsigned`](is_number_unsigned.md), and [`is_number_float`](is_number_float.md)),
[`is_discarded`](is_discarded.md), [`is_binary`](is_binary.md), [`is_primitive`](is_primitive.md), and
[`is_structured`](is_structured.md) rely on it.

## Notes

There are three enumeration entries (number_integer, number_unsigned, and number_float), because the library
distinguishes these three types for numbers: [`number_unsigned_t`](number_unsigned_t.md) is used for unsigned integers,
[`number_integer_t`](number_integer_t.md) is used for signed integers, and [`number_float_t`](number_float_t.md) is used
for floating-point numbers or to approximate integers which do not fit in the limits of their respective type.

## Version history

- Added in version 1.0.0.
- Added unsigned integer type in version 2.0.0.
- Added binary type in version 3.8.0.
