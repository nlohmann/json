# <small>nlohmann::</small>json_view

<small>Defined in header `<nlohmann/json_view.hpp>`</small>

```cpp
using json_view = basic_json_view<json>;
```

This type is a [`basic_json_view`](basic_json_view/index.md) of a value of a [`json_document`](json_document.md).

## Examples

??? example

    The example below demonstrates how to use the type `nlohmann::json_view`.

    ```cpp
    --8<-- "examples/json_view.cpp"
    ```

    Output:

    ```json
    --8<-- "examples/json_view.output"
    ```

## See also

- [json_document](json_document.md) - the document type this view refers into
- [ordered_json_view](ordered_json_view.md) - the corresponding view for `ordered_json_document`

## Version history

Since version 3.13.0.
