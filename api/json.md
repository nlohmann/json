# <small>nlohmann::</small>json

```cpp
using json = basic_json<>;
```

This type is the default specialization of the [basic_json](basic_json/index.md) class which uses the standard template
types.

## Examples

??? example

    The example below demonstrates how to use the type `nlohmann::json`.

    ```cpp
    #include <iostream>
    #include <iomanip>
    #include <nlohmann/json.hpp>
    
    using nlohmann::json;
    
    int main()
    {
        // create a JSON object
        json j =
        {
            {"pi", 3.141},
            {"happy", true},
            {"name", "Niels"},
            {"nothing", nullptr},
            {
                "answer", {
                    {"everything", 42}
                }
            },
            {"list", {1, 0, 2}},
            {
                "object", {
                    {"currency", "USD"},
                    {"value", 42.99}
                }
            }
        };
    
        // add new values
        j["new"]["key"]["value"] = {"another", "list"};
    
        // count elements
        auto s = j.size();
        j["size"] = s;
    
        // pretty print with indent of 4 spaces
        std::cout << std::setw(4) << j << '\n';
    }
    
    ```
    
    Output:
    
    ```json
    {
        "answer": {
            "everything": 42
        },
        "happy": true,
        "list": [
            1,
            0,
            2
        ],
        "name": "Niels",
        "new": {
            "key": {
                "value": [
                    "another",
                    "list"
                ]
            }
        },
        "nothing": null,
        "object": {
            "currency": "USD",
            "value": 42.99
        },
        "pi": 3.141,
        "size": 8
    }
    
    ```

## See also

- [`basic_json`](basic_json/index.md) - the underlying class template
- [`ordered_json`](ordered_json.md) - specialization that preserves the insertion order of object keys
- [Types](../features/types/index.md) - the JSON value types and how they are stored
- [Converting values](../features/conversions.md) - get values out of a JSON value and put values in
- [Creating JSON values](../features/creating_values.md) - all the ways to build a JSON value

## Version history

Added in version 1.0.0.
