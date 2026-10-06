# <small>nlohmann::</small>json_document

<small>Defined in header `<nlohmann/json_view.hpp>`</small>

```cpp
using json_document = basic_json_document<json>;
```

This type is a [`basic_json_document`](basic_json_document/index.md) of the default [`json`](json.md)
specialization.

## Examples

??? example

    The example below demonstrates how to use the type `nlohmann::json_document`.

    ```cpp
    --8<-- "examples/json_document.cpp"
    ```

    Output:

    ```json
    --8<-- "examples/json_document.output"
    ```

## See also

- [json_view](json_view.md) - a view of a value of a `json_document`
- [ordered_json_document](ordered_json_document.md) - the corresponding document for `ordered_json`

## Version history

Since version 3.13.0.
