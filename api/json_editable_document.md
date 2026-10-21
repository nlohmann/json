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
    #include <iostream>
    #include <nlohmann/json_view.hpp>
    
    using json = nlohmann::json;
    using json_editable_document = nlohmann::json_editable_document;
    using json_editable_view = nlohmann::json_editable_view;
    
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

    ```json
    {"name": "cache", "host": "db1", "port": 6379, "price": 19.90}
    
    {"name":"cache","host":"db2","port":6379,"price":19.90,"retries":3}
    {"host":"db2","name":"cache","port":6379,"price":19.9,"retries":3}
    
    ```

## See also

- [json_editable_view](json_editable_view.md) - a view of a value of a `json_editable_document`
- [json_document](json_document.md) - the read-only document this type adds edits to
- [ordered_json_editable_document](ordered_json_editable_document.md) - the corresponding editable document for
  `ordered_json`
- [Edits](basic_json_document/index.md#edits) - what an edit guarantees

## Version history

Since version 3.13.0.
