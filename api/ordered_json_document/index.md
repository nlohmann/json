# nlohmann::ordered_json_document

Defined in header `<nlohmann/json_view.hpp>`

```
using ordered_json_document = basic_json_document<ordered_json, view_mode::read_only>;
```

This type is a [`basic_json_document`](https://json.nlohmann.me/api/basic_json_document/index.md) of the [`ordered_json`](https://json.nlohmann.me/api/ordered_json/index.md) specialization: [`materialize()`](https://json.nlohmann.me/api/basic_json_view/materialize/index.md) on one of its views preserves the insertion order of object keys, instead of sorting them like [`json_document`](https://json.nlohmann.me/api/json_document/index.md) does.

## Examples

Example

The example below demonstrates how `ordered_json_document` preserves the insertion order of object keys when materializing.

```
#include <iostream>
#include <nlohmann/json_view.hpp>

using nlohmann::ordered_json_document;

int main()
{
    // ordered_json_document is basic_json_document<nlohmann::ordered_json>:
    // materialize() preserves the insertion (source) order of object keys,
    // instead of sorting them like json_document does
    ordered_json_document doc = ordered_json_document::parse(R"({"z": 1, "a": 2, "m": 3})");
    std::cout << doc.root().materialize().dump() << '\n';
}
```

Output:

```
{"z":1,"a":2,"m":3}
```

## See also

- [`ordered_json_view`](https://json.nlohmann.me/api/ordered_json_view/index.md) - a view of a value of an `ordered_json_document`
- [`json_document`](https://json.nlohmann.me/api/json_document/index.md) - the corresponding document for the default `json` specialization
- [Object Order](https://json.nlohmann.me/features/object_order/index.md) - preserving the insertion order of object keys
- [Zero-copy JSON views](https://json.nlohmann.me/features/json_view/index.md) - how to parse, inspect and edit a document without building a tree

## Version history

Added in version 3.13.0 unreleased.
