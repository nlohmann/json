# <small>nlohmann::</small>ordered_json_editable_view

<small>Defined in header `<nlohmann/json_view.hpp>`</small>

```cpp
using ordered_json_editable_view = basic_json_view<ordered_json, true>;
```

This type is a [`basic_json_view`](basic_json_view/index.md) of a value of an
[`ordered_json_editable_document`](ordered_json_editable_document.md), the corresponding view for
[`ordered_json_view`](ordered_json_view.md) the way [`json_editable_view`](json_editable_view.md) is for
[`json_view`](json_view.md).

## Examples

??? example

    The example below is the same as [`ordered_json_editable_document`'s](ordered_json_editable_document.md): the
    views `set` returns see the document's member order preserved on `materialize()`, unlike for a
    [`json_editable_document`](json_editable_document.md).

    ```cpp
    --8<-- "examples/ordered_json_editable_document.cpp"
    ```

    Output:

    ```json
    --8<-- "examples/ordered_json_editable_document.output"
    ```

## See also

- [ordered_json_editable_document](ordered_json_editable_document.md) - the document type this view refers into
- [ordered_json_view](ordered_json_view.md) - the corresponding read-only view
- [json_editable_view](json_editable_view.md) - the corresponding view for `json_editable_document`

## Version history

Since version 3.13.0.
