# <small>nlohmann::basic_json_view::</small>is_number

```cpp
bool is_number() const noexcept;
```

This function returns `#!cpp true` if and only if the value is a number, i.e. an integer, unsigned integer, or floating-point value. It is defined as `#!cpp is_number_integer() || is_number_float()`.

## Return value

`#!cpp true` if the type is a number, `#!cpp false` otherwise.

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
- [is_number_unsigned](is_number_unsigned.md) - return whether the value is an unsigned integer number
- [is_number_float](is_number_float.md) - return whether the value is a floating-point number
- [`BasicJsonType::is_number`](../basic_json/is_number.md) - the corresponding function of `basic_json`

## Version history

- Added in version 3.13.0.
