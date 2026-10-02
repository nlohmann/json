# <small>nlohmann::</small>json_editable_view

<small>Defined in header `<nlohmann/json_view.hpp>`</small>

```cpp
using json_editable_view = basic_json_view<json, true>;
```

This type is a [`basic_json_view`](basic_json_view/index.md) of a value of a
[`json_editable_document`](json_editable_document.md). It offers the same read-only interface as
[`json_view`](json_view.md); what is different is what it can be a view *of* -- a value that
[`set`](basic_json_document/set.md) and [`push_back`](basic_json_document/push_back.md) can change, with every view
still referring to it seeing the change, see [Edits](basic_json_document/index.md#edits).

## Examples

??? example

    The example below is the same as [`json_editable_document`'s](json_editable_document.md): every view read back
    out of the document -- `#!cpp doc.root()` and the views nested under it -- sees the edits made through `set`.

    ```cpp
    --8<-- "examples/json_editable_document.cpp"
    ```

    Output:

    ```json
    --8<-- "examples/json_editable_document.output"
    ```

## See also

- [json_editable_document](json_editable_document.md) - the document type this view refers into
- [json_view](json_view.md) - the corresponding read-only view
- [ordered_json_editable_view](ordered_json_editable_view.md) - the corresponding view for
  `ordered_json_editable_document`

## Version history

Since version 3.13.0.
