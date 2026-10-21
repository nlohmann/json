# <small>nlohmann::basic_json_view::</small>is_number_float

```cpp
bool is_number_float() const noexcept;
```

This function returns `#!cpp true` if and only if the value is a floating-point number.

## Return value

`#!cpp true` if the type is `#!cpp value_t::number_float`, `#!cpp false` otherwise.

## Exception safety

No-throw guarantee: this function never throws exceptions.

## Complexity

Constant.

## Notes

As for [`BasicJsonType::parse`](../basic_json/parse.md), an integer literal that does not fit into the 64-bit
integer type is classified as a floating-point number, so `is_number_float()` can be `#!cpp true` even for an
integer-looking token in the source text.

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
- [`BasicJsonType::is_number_float`](../basic_json/is_number_float.md) - the corresponding function of `basic_json`

## Version history

- Added in version 3.13.0.
