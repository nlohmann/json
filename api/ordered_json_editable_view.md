# <small>nlohmann::</small>ordered_json_editable_view

<small>Defined in header `<nlohmann/json_view.hpp>`</small>

```cpp
using ordered_json_editable_view = basic_json_view<ordered_json, view_mode::editable>;
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
    #include <iostream>
    #include <nlohmann/json_view.hpp>
    
    using nlohmann::ordered_json_editable_document;
    
    int main()
    {
        // ordered_json_editable_document is basic_json_document<nlohmann::ordered_json, nlohmann::view_mode::editable>
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

- [ordered_json_editable_document](ordered_json_editable_document.md) - the document type this view refers into
- [ordered_json_view](ordered_json_view.md) - the corresponding read-only view
- [json_editable_view](json_editable_view.md) - the corresponding view for `json_editable_document`

## Version history

Added in version 3.13.0.
