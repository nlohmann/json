# <small>nlohmann::</small>json_document

<small>Defined in header `<nlohmann/json_view.hpp>`</small>

```cpp
using json_document = basic_json_document<json>;
```

This type is a [`basic_json_document`](basic_json_document/index.md) of the default [`json`](json.md)
specialization.

## Examples

??? example

    The example below demonstrates how to use the type `nlohmann::json_document`.

    ```cpp
    #include <iostream>
    #include <nlohmann/json_view.hpp>
    
    using json_document = nlohmann::json_document;
    
    int main()
    {
        std::cout << std::boolalpha;
    
        // json_document is basic_json_document<nlohmann::json>: same value types
        // and containers as the ordinary json specialization
        json_document doc = json_document::parse(R"({"pi": 3.14, "numbers": [1, 2, 3]})");
    
        std::cout << doc.root().is_object() << '\n';
        std::cout << doc.root().materialize().dump() << '\n';
    }
    
    ```

    Output:

    ```json
    true
    {"numbers":[1,2,3],"pi":3.14}
    
    ```

## See also

- [json_view](json_view.md) - a view of a value of a `json_document`
- [ordered_json_document](ordered_json_document.md) - the corresponding document for `ordered_json`

## Version history

Since version 3.13.0.
