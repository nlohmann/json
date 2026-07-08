# nlohmann::json

```
using json = basic_json<>;
```

This type is the default specialization of the [basic_json](https://json.nlohmann.me/api/basic_json/index.md) class which uses the standard template types.

## Examples

Example

The example below demonstrates how to use the type `nlohmann::json`.

```
#include <iostream>
#include <iomanip>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

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

```
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

## Version history

Since version 1.0.0.
