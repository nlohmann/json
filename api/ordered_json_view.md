# <small>nlohmann::</small>ordered_json_view

<small>Defined in header `<nlohmann/json_view.hpp>`</small>

```cpp
using ordered_json_view = basic_json_view<ordered_json>;
```

This type is a [`basic_json_view`](basic_json_view/index.md) of a value of an
[`ordered_json_document`](ordered_json_document.md).

## Examples

??? example

    The example below demonstrates how to use the type `nlohmann::ordered_json_view`.

    ```cpp
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

    ```json
    true 2
    
    ```

## See also

- [ordered_json_document](ordered_json_document.md) - the document type this view refers into
- [json_view](json_view.md) - the corresponding view for `json_document`

## Version history

Since version 3.13.0.
