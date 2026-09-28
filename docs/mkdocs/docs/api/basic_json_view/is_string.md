# <small>nlohmann::basic_json_view::</small>is_string

```cpp
bool is_string() const noexcept;
```

This function returns `#!cpp true` if and only if the value is a string.

## Return value

`#!cpp true` if the type is a string, `#!cpp false` otherwise.

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

- [source_offset](source_offset.md) - byte offset of this value in the document's source text
- [`BasicJsonType::is_string`](../basic_json/is_string.md) - the corresponding function of `basic_json`

## Version history

- Added in version 3.13.0.
