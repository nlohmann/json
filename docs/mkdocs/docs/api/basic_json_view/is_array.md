# <small>nlohmann::basic_json_view::</small>is_array

```cpp
bool is_array() const noexcept;
```

This function returns `#!cpp true` if and only if the value is an array.

## Return value

`#!cpp true` if the type is an array, `#!cpp false` otherwise.

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

- [is_structured](is_structured.md) - return whether the type is structured
- [size](size.md), [empty](empty.md) - the number of elements, and whether there are none
- [`BasicJsonType::is_array`](../basic_json/is_array.md) - the corresponding function of `basic_json`

## Version history

- Added in version 3.13.0.
