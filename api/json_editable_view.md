# <small>nlohmann::</small>json_editable_view

<small>Defined in header `<nlohmann/json_view.hpp>`</small>

```cpp
using json_editable_view = basic_json_view<json, view_mode::editable>;
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

    ```json
    {"name": "cache", "host": "db1", "port": 6379, "price": 19.90}
    
    {"name":"cache","host":"db2","port":6379,"price":19.90,"retries":3}
    {"host":"db2","name":"cache","port":6379,"price":19.9,"retries":3}
    
    ```

## See also

- [json_editable_document](json_editable_document.md) - the document type this view refers into
- [json_view](json_view.md) - the corresponding read-only view
- [ordered_json_editable_view](ordered_json_editable_view.md) - the corresponding view for
  `ordered_json_editable_document`

## Version history

Added in version 3.13.0.
