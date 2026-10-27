# nlohmann::ordered_json_editable_document

Defined in header `<nlohmann/json_view.hpp>`

```
using ordered_json_editable_document = basic_json_document<ordered_json, view_mode::editable>;
```

This type is an **editable** [`basic_json_document`](https://json.nlohmann.me/api/basic_json_document/index.md) of the [`ordered_json`](https://json.nlohmann.me/api/ordered_json/index.md) specialization: [`set`](https://json.nlohmann.me/api/basic_json_document/set/index.md) and [`push_back`](https://json.nlohmann.me/api/basic_json_document/push_back/index.md) change values after parsing, as for [`json_editable_document`](https://json.nlohmann.me/api/json_editable_document/index.md), and [`materialize()`](https://json.nlohmann.me/api/basic_json_view/materialize/index.md) preserves the document order of object members — including members [`set`](https://json.nlohmann.me/api/basic_json_document/set/index.md) added — instead of sorting them like [`json_editable_document`](https://json.nlohmann.me/api/json_editable_document/index.md) does.

## Examples

Example

The example below edits a document with `set`, then shows that `materialize()` keeps the member order of the source text (with the new member at the end) for `ordered_json_editable_document`, where it would sort the members alphabetically for [`json_editable_document`](https://json.nlohmann.me/api/json_editable_document/index.md).

```
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

```
{"z":1,"a":2,"m":3,"b":4}
```

## See also

- [`ordered_json_editable_view`](https://json.nlohmann.me/api/ordered_json_editable_view/index.md) - a view of a value of an `ordered_json_editable_document`
- [`ordered_json_document`](https://json.nlohmann.me/api/ordered_json_document/index.md) - the read-only document this type adds edits to
- [`json_editable_document`](https://json.nlohmann.me/api/json_editable_document/index.md) - the corresponding editable document for the default `json` specialization
- [Object Order](https://json.nlohmann.me/features/object_order/index.md) - preserving the insertion order of object keys
- [Edits](https://json.nlohmann.me/api/basic_json_document/#edits) - what an edit guarantees
- [Zero-copy JSON views](https://json.nlohmann.me/features/json_view/#editing-a-document) - editing a document in place and writing it back

## Version history

Added in version 3.13.0 unreleased.
