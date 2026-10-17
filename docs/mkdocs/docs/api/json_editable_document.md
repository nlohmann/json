# <small>nlohmann::</small>json_editable_document

<small>Defined in header `<nlohmann/json_view.hpp>`</small>

```cpp
using json_editable_document = basic_json_document<json, true>;
```

This type is an **editable** [`basic_json_document`](basic_json_document/index.md) of the default
[`json`](json.md) specialization: in addition to everything [`json_document`](json_document.md) offers,
[`set`](basic_json_document/set.md) and [`push_back`](basic_json_document/push_back.md) change values after
parsing, without ever rewriting the source text -- see [Edits](basic_json_document/index.md#edits) and
[Editing a document](../features/json_view.md#editing-a-document).

## Examples

??? example

    The example below patches two fields of a small configuration document -- changing one and adding another --
    and dumps it back out with the member order and the spelling of the untouched number preserved, something a
    plain [`json`](json.md) value cannot do.

    ```cpp
    --8<-- "examples/json_editable_document.cpp"
    ```

    Output:

    ```json
    --8<-- "examples/json_editable_document.output"
    ```

## See also

- [json_editable_view](json_editable_view.md) - a view of a value of a `json_editable_document`
- [json_document](json_document.md) - the read-only document this type adds edits to
- [ordered_json_editable_document](ordered_json_editable_document.md) - the corresponding editable document for
  `ordered_json`
- [Edits](basic_json_document/index.md#edits) - what an edit guarantees

## Version history

Since version 3.13.0.
