# nlohmann::json_view

Defined in header `<nlohmann/json_view.hpp>`

```
using json_view = basic_json_view<json, view_mode::read_only>;
```

This type is a [`basic_json_view`](https://json.nlohmann.me/api/basic_json_view/index.md) of a value of a [`json_document`](https://json.nlohmann.me/api/json_document/index.md).

## Examples

Example

The example below demonstrates how to use the type `nlohmann::json_view`.

```
#include <iostream>
#include <nlohmann/json_view.hpp>

int main()
{
    std::cout << std::boolalpha;

    // json_view is basic_json_view<nlohmann::json>: a read-only handle
    // returned by json_document::root()
    nlohmann::json_document doc = nlohmann::json_document::parse("[1, 2, 3]");
    nlohmann::json_view v = doc.root();

    std::cout << v.is_array() << ' ' << v.size() << '\n';
}
```

Output:

```
true 3
```

## See also

- [`json_document`](https://json.nlohmann.me/api/json_document/index.md) - the document type this view refers into
- [`ordered_json_view`](https://json.nlohmann.me/api/ordered_json_view/index.md) - the corresponding view for `ordered_json_document`
- [Zero-copy JSON views](https://json.nlohmann.me/features/json_view/index.md) - how to parse, inspect and edit a document without building a tree

## Version history

Added in version 3.13.0 unreleased.
