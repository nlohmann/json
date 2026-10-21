# <small>nlohmann::</small>ordered_json_document

<small>Defined in header `<nlohmann/json_view.hpp>`</small>

```cpp
using ordered_json_document = basic_json_document<ordered_json>;
```

This type is a [`basic_json_document`](basic_json_document/index.md) of the [`ordered_json`](ordered_json.md)
specialization: [`materialize()`](basic_json_view/materialize.md) on one of its views preserves the insertion order
of object keys, instead of sorting them like [`json_document`](json_document.md) does.

## Examples

??? example

    The example below demonstrates how `ordered_json_document` preserves the insertion order of object keys when
    materializing.

    ```cpp
    #include <iostream>
    #include <nlohmann/json_view.hpp>
    
    using ordered_json_document = nlohmann::ordered_json_document;
    
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

    ```json
    {"z":1,"a":2,"m":3}
    
    ```

## See also

- [ordered_json_view](ordered_json_view.md) - a view of a value of an `ordered_json_document`
- [json_document](json_document.md) - the corresponding document for the default `json` specialization
- [Object Order](../features/object_order.md)

## Version history

Since version 3.13.0.
