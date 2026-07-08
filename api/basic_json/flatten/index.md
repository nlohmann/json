# nlohmann::basic_json::flatten

```
basic_json flatten() const;
```

The function creates a JSON object whose keys are JSON pointers (see [RFC 6901](https://tools.ietf.org/html/rfc6901)) and whose values are all primitive (see [`is_primitive()`](https://json.nlohmann.me/api/basic_json/is_primitive/index.md) for more information). The original JSON value can be restored using the [`unflatten()`](https://json.nlohmann.me/api/basic_json/unflatten/index.md) function.

## Return value

an object that maps JSON pointers to primitive values

## Exception safety

Strong exception safety: if an exception occurs, the original value stays intact.

## Complexity

Linear in the size of the JSON value.

## Notes

Empty objects and arrays are flattened to `null` and will not be reconstructed correctly by the [`unflatten()`](https://json.nlohmann.me/api/basic_json/unflatten/index.md) function.

## Examples

Example

The following code shows how a JSON object is flattened to an object whose keys consist of JSON pointers.

```
#include <iostream>
#include <iomanip>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

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

```
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

## See also

- [unflatten](https://json.nlohmann.me/api/basic_json/unflatten/index.md) the reverse function

## Version history

- Added in version 2.0.0.
