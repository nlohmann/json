# <small>nlohmann::basic_json_view::</small>is_number_integer

```cpp
bool is_number_integer() const noexcept;
```

This function returns `#!cpp true` if and only if the value is an integer or unsigned integer number.

## Return value

`#!cpp true` if the type is `#!cpp value_t::number_integer` or `#!cpp value_t::number_unsigned`, `#!cpp false` otherwise.

## Exception safety

No-throw guarantee: this function never throws exceptions.

## Complexity

Constant.

## Notes

As for [`BasicJsonType::is_number_integer`](../basic_json/is_number_integer.md), this includes unsigned integer
values; use [`is_number_unsigned`](is_number_unsigned.md) to test for those specifically.

## Examples

??? example

    The example below classifies several parsed documents by the type of their root value, without materializing any
    of them into a `BasicJsonType` value.

    ```cpp
    --8<-- "examples/basic_json_view__type_predicates.cpp"
    ```

    Output:

    ```json
    --8<-- "examples/basic_json_view__type_predicates.output"
    ```

## See also

- [is_number](is_number.md) - return whether the value is a number
- [is_number_unsigned](is_number_unsigned.md) - return whether the value is an unsigned integer number
- [`BasicJsonType::is_number_integer`](../basic_json/is_number_integer.md) - the corresponding function of `basic_json`

## Version history

- Added in version 3.13.0.
