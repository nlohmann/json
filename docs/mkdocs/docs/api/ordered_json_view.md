# <small>nlohmann::</small>ordered_json_view

<small>Defined in header `<nlohmann/json_view.hpp>`</small>

```cpp
using ordered_json_view = basic_json_view<ordered_json>;
```

This type is a [`basic_json_view`](basic_json_view/index.md) of a value of an
[`ordered_json_document`](ordered_json_document.md).

## Examples

??? example

    The example below demonstrates how to use the type `nlohmann::ordered_json_view`.

    ```cpp
    --8<-- "examples/ordered_json_view.cpp"
    ```

    Output:

    ```json
    --8<-- "examples/ordered_json_view.output"
    ```

## See also

- [ordered_json_document](ordered_json_document.md) - the document type this view refers into
- [json_view](json_view.md) - the corresponding view for `json_document`

## Version history

Since version 3.13.0.
