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

!!! note "Ordering"

    The order of types is as follows:

    1. `null`
    2. `boolean`
    3. `number_integer`, `number_unsigned`, `number_float`
    4. `object`
    5. `array`
    6. `string`
    7. `binary`

    `discarded` is unordered.

!!! note "Types of numbers"

    There are three enumerators for numbers (`number_integer`, `number_unsigned`, and `number_float`) to distinguish
    between different types of numbers:

      - [`number_unsigned_t`](number_unsigned_t.md) for unsigned integers
      - [`number_integer_t`](number_integer_t.md) for signed integers
      - [`number_float_t`](number_float_t.md) for floating-point numbers or to approximate integers which do not fit
        into the limits of their respective type

!!! warning "Comparison operators"

    `operator<` and `operator<=>` (since C++20) are overloaded and compare according to the ordering described above.
    Until C++20 all other relational and equality operators yield results according to the integer value of each
    enumerator. Since C++20 some compilers consider the _rewritten candidates_ generated from `operator<=>` during
    overload resolution, while others do not. For predictable and portable behavior use:

      - `operator<` or `operator<=>` when wanting to compare according to the order described above
      - `operator==` or `operator!=` when wanting to compare according to each enumerators integer value

## Examples

??? example

    The following code how `type()` queries the `value_t` for all JSON types.
    
    ```cpp
    --8<-- "examples/type.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/type.output"
    ```

## Version history

- Added in version 1.0.0.
- Added unsigned integer type in version 2.0.0.
- Added binary type in version 3.8.0.
