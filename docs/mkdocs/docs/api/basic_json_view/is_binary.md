# <small>nlohmann::basic_json_view::</small>is_binary

```cpp
bool is_binary() const noexcept;
```

This function always returns `#!cpp false`: a JSON text has no binary values, so a view can never refer to one. The
function exists for interface parity with [`BasicJsonType::is_binary`](../basic_json/is_binary.md).

## Return value

`#!cpp false`, always.

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

- [type](type.md) - return the type of the value
- [`BasicJsonType::is_binary`](../basic_json/is_binary.md) - the corresponding function of `basic_json`

## Version history

- Added in version 3.13.0.
