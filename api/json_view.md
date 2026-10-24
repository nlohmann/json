# <small>nlohmann::</small>json_view

<small>Defined in header `<nlohmann/json_view.hpp>`</small>

```cpp
using json_view = basic_json_view<json>;
```

This type is a [`basic_json_view`](basic_json_view/index.md) of a value of a [`json_document`](json_document.md).

## Examples

??? example

    The example below demonstrates how to use the type `nlohmann::json_view`.

    ```cpp
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

    ```json
    true 3
    
    ```

## See also

- [json_document](json_document.md) - the document type this view refers into
- [ordered_json_view](ordered_json_view.md) - the corresponding view for `ordered_json_document`

## Version history

Added in version 3.13.0.
