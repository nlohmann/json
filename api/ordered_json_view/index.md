# nlohmann::ordered_json_view

Defined in header `<nlohmann/json_view.hpp>`

```
using ordered_json_view = basic_json_view<ordered_json, view_mode::read_only>;
```

This type is a [`basic_json_view`](https://json.nlohmann.me/api/basic_json_view/index.md) of a value of an [`ordered_json_document`](https://json.nlohmann.me/api/ordered_json_document/index.md).

## Examples

Example

The example below demonstrates how to use the type `nlohmann::ordered_json_view`.

```
#include <iostream>
#include <nlohmann/json_view.hpp>

int main()
{
    nlohmann::ordered_json_document doc = nlohmann::ordered_json_document::parse(R"({"z": 1, "a": 2})");
    nlohmann::ordered_json_view v = doc.root();

    std::cout << std::boolalpha << v.is_object() << ' ' << v.size() << '\n';
}
```

Output:

```
true 2
```

## See also

- [ordered_json_document](https://json.nlohmann.me/api/ordered_json_document/index.md) - the document type this view refers into
- [json_view](https://json.nlohmann.me/api/json_view/index.md) - the corresponding view for `json_document`

## Version history

Added in version 3.13.0 unreleased.
