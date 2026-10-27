# nlohmann::json_editable_document

Defined in header `<nlohmann/json_view.hpp>`

```
using json_editable_document = basic_json_document<json, view_mode::editable>;
```

This type is an **editable** [`basic_json_document`](https://json.nlohmann.me/api/basic_json_document/index.md) of the default [`json`](https://json.nlohmann.me/api/json/index.md) specialization: in addition to everything [`json_document`](https://json.nlohmann.me/api/json_document/index.md) offers, [`set`](https://json.nlohmann.me/api/basic_json_document/set/index.md) and [`push_back`](https://json.nlohmann.me/api/basic_json_document/push_back/index.md) change values after parsing, without ever rewriting the source text — see [Edits](https://json.nlohmann.me/api/basic_json_document/#edits) and [Editing a document](https://json.nlohmann.me/features/json_view/#editing-a-document).

## Examples

Example

The example below patches two fields of a small configuration document — changing one and adding another — and dumps it back out with the member order and the spelling of the untouched number preserved, something a plain [`json`](https://json.nlohmann.me/api/json/index.md) value cannot do.

```
#include <iostream>
#include <nlohmann/json_view.hpp>

using nlohmann::json;
using nlohmann::json_editable_document;
using nlohmann::json_editable_view;

int main()
{
    // a configuration file, as it might be read from disk
    const std::string text = R"({"name": "cache", "host": "db1", "port": 6379, "price": 19.90})";
    std::cout << text << "\n\n";

    // patch two fields -- "price" is never touched
    json_editable_document doc = json_editable_document::parse(text);
    doc.set(doc.root(), "host", "db2");
    doc.set(doc.root(), "retries", 3);

    // member order (the new member at the end) and the untouched number's
    // exact spelling survive
    std::cout << doc.root().dump(-1, ' ', false, json_editable_view::number_format::source) << '\n';

    // the same patch on a plain json value: keys are sorted (object_t is a
    // std::map), and "price" is rewritten even though the patch never
    // touched it
    json plain = json::parse(text);
    plain["host"] = "db2";
    plain["retries"] = 3;
    std::cout << plain.dump() << '\n';
}
```

Output:

```
{"name": "cache", "host": "db1", "port": 6379, "price": 19.90}

{"name":"cache","host":"db2","port":6379,"price":19.90,"retries":3}
{"host":"db2","name":"cache","port":6379,"price":19.9,"retries":3}
```

## See also

- [`json_editable_view`](https://json.nlohmann.me/api/json_editable_view/index.md) - a view of a value of a `json_editable_document`
- [`json_document`](https://json.nlohmann.me/api/json_document/index.md) - the read-only document this type adds edits to
- [`ordered_json_editable_document`](https://json.nlohmann.me/api/ordered_json_editable_document/index.md) - the corresponding editable document for `ordered_json`
- [Edits](https://json.nlohmann.me/api/basic_json_document/#edits) - what an edit guarantees

## Version history

Added in version 3.13.0 unreleased.
