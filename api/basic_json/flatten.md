# <small>nlohmann::basic_json::</small>flatten

```cpp
basic_json flatten() const;
```

The function creates a JSON object whose keys are JSON pointers (see [RFC 6901](https://tools.ietf.org/html/rfc6901))
and whose values are all primitive (see [`is_primitive()`](is_primitive.md) for more information). The original JSON
value can be restored using the [`unflatten()`](unflatten.md) function.
    
## Return value

an object that maps JSON pointers to primitive values

## Exception safety

Strong exception safety: if an exception occurs, the original value stays intact.

## Complexity

Linear in the size of the JSON value.

## Notes

Empty objects and arrays are flattened to `#!json null` and will not be reconstructed correctly by the
[`unflatten()`](unflatten.md) function.

## Examples

??? example "Example: flatten a JSON object"

    The following code shows how a JSON object is flattened to an object whose keys consist of JSON pointers.
    
    ```cpp
    #include <iostream>
    #include <iomanip>
    #include <nlohmann/json.hpp>
    
    using nlohmann::json;
    
    int main()
    {
        // create JSON value
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
    
        // call flatten()
        std::cout << std::setw(4) << j.flatten() << '\n';
    }
    
    ```
    
    Output:
    
    ```json
    {
        "/answer/everything": 42,
        "/happy": true,
        "/list/0": 1,
        "/list/1": 0,
        "/list/2": 2,
        "/name": "Niels",
        "/nothing": null,
        "/object/currency": "USD",
        "/object/value": 42.99,
        "/pi": 3.141
    }
    
    ```

??? example "Example: empty objects and arrays are flattened to `#!json null`"

    The following code shows that an empty object and an empty array are both flattened to `#!json null`, and that
    `unflatten()` restores them as `#!json null` rather than as empty containers.

    ```cpp
    #include <iostream>
    #include <iomanip>
    #include <nlohmann/json.hpp>
    
    using nlohmann::json;
    
    int main()
    {
        // create a JSON value with an empty object and an empty array
        json j =
        {
            {"empty_object", json::object()},
            {"empty_array", json::array()},
            {"name", "Niels"}
        };
    
        // call flatten()
        json flattened = j.flatten();
        std::cout << std::setw(4) << flattened << "\n\n";
    
        // the empty containers cannot be restored by unflatten()
        std::cout << std::setw(4) << flattened.unflatten() << '\n';
    }
    
    ```

    Output:

    ```json
    {
        "/empty_array": null,
        "/empty_object": null,
        "/name": "Niels"
    }
    
    {
        "empty_array": null,
        "empty_object": null,
        "name": "Niels"
    }
    
    ```

## See also

- [unflatten](unflatten.md) the reverse function

## Version history

- Added in version 2.0.0.
