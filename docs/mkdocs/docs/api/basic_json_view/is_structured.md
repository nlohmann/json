# <small>nlohmann::basic_json_view::</small>is_structured

```cpp
bool is_structured() const noexcept;
```

This function returns `#!cpp true` if and only if the value is structured, i.e. an array or an object. It is defined as `#!cpp is_array() || is_object()`.

## Return value

`#!cpp true` if the type is structured, `#!cpp false` otherwise.

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

- [is_primitive](is_primitive.md) - return whether the type is primitive
- [size](size.md), [empty](empty.md) - the number of elements, and whether there are none
- [`BasicJsonType::is_structured`](../basic_json/is_structured.md) - the corresponding function of `basic_json`

## Version history

- Added in version 3.13.0.
