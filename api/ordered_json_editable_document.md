# <small>nlohmann::</small>ordered_json_editable_document

<small>Defined in header `<nlohmann/json_view.hpp>`</small>

```cpp
using ordered_json_editable_document = basic_json_document<ordered_json, true>;
```

This type is an **editable** [`basic_json_document`](basic_json_document/index.md) of the
[`ordered_json`](ordered_json.md) specialization: [`set`](basic_json_document/set.md) and
[`push_back`](basic_json_document/push_back.md) change values after parsing, as for
[`json_editable_document`](json_editable_document.md), and
[`materialize()`](basic_json_view/materialize.md) preserves the document order of object members -- including
members [`set`](basic_json_document/set.md) added -- instead of sorting them like
[`json_editable_document`](json_editable_document.md) does.

## Examples

??? example

    The example below edits a document with `set`, then shows that `materialize()` keeps the member order of the
    source text (with the new member at the end) for `ordered_json_editable_document`, where it would sort the
    members alphabetically for [`json_editable_document`](json_editable_document.md).

    ```cpp
    #include <iostream>
    #include <nlohmann/json_view.hpp>
    
    using ordered_json_editable_document = nlohmann::ordered_json_editable_document;
    
    int main()
    {
        // ordered_json_editable_document is basic_json_document<nlohmann::ordered_json, true>
        ordered_json_editable_document doc = ordered_json_editable_document::parse(R"({"z": 1, "a": 2, "m": 3})");
        doc.set(doc.root(), "b", 4); // set() always appends a new member at the end
    
        // materialize() preserves the document order (with "b" at the end),
        // instead of sorting the keys the way json_editable_document does
        std::cout << doc.root().materialize().dump() << '\n';
    }
    
    ```

    Output:

    ```json
    {"z":1,"a":2,"m":3,"b":4}
    
    ```

## See also

- [ordered_json_editable_view](ordered_json_editable_view.md) - a view of a value of an
  `ordered_json_editable_document`
- [ordered_json_document](ordered_json_document.md) - the read-only document this type adds edits to
- [json_editable_document](json_editable_document.md) - the corresponding editable document for the default `json`
  specialization
- [Object Order](../features/object_order.md)
- [Edits](basic_json_document/index.md#edits) - what an edit guarantees

## Version history

Since version 3.13.0.
