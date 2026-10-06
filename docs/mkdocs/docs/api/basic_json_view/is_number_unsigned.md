# <small>nlohmann::basic_json_view::</small>is_number_unsigned

```cpp
bool is_number_unsigned() const noexcept;
```

This function returns `#!cpp true` if and only if the value is an unsigned integer number.

## Return value

`#!cpp true` if the type is `#!cpp value_t::number_unsigned`, `#!cpp false` otherwise.

## Exception safety

No-throw guarantee: this function never throws exceptions.

## Complexity

Constant.

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

- [is_number_integer](is_number_integer.md) - return whether the value is an integer or unsigned integer number
- [`BasicJsonType::is_number_unsigned`](../basic_json/is_number_unsigned.md) - the corresponding function of `basic_json`

## Version history

- Added in version 3.13.0.
