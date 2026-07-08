# nlohmann::basic_json::unflatten

```
basic_json unflatten() const;
```

The function restores the arbitrary nesting of a JSON value that has been flattened before using the [`flatten()`](https://json.nlohmann.me/api/basic_json/flatten/index.md) function. The JSON value must meet certain constraints:

1. The value must be an object.
1. The keys must be JSON pointers (see [RFC 6901](https://tools.ietf.org/html/rfc6901))
1. The mapped values must be primitive JSON types.

## Return value

the original JSON from a flattened version

## Exception safety

Strong exception safety: if an exception occurs, the original value stays intact.

## Exceptions

The function can throw the following exceptions:

- Throws [`type_error.314`](https://json.nlohmann.me/home/exceptions/#jsonexceptiontype_error314) if value is not an object
- Throws [`type_error.315`](https://json.nlohmann.me/home/exceptions/#jsonexceptiontype_error315) if object values are not primitive
- Throws [`type_error.313`](https://json.nlohmann.me/home/exceptions/#jsonexceptiontype_error313) if a key (JSON pointer) leads to a conflicting nesting; example: `"invalid value to unflatten"`
- Throws [`parse_error.109`](https://json.nlohmann.me/home/exceptions/#jsonexceptionparse_error109) if an array index in a key is not a number; example: `"array index 'one' is not a number"`

## Complexity

Linear in the size of the JSON value.

## Notes

Empty objects and arrays are flattened by [`flatten()`](https://json.nlohmann.me/api/basic_json/flatten/index.md) to `null` values and cannot unflattened to their original type. Apart from this example, for a JSON value `j`, the following is always true: `j == j.flatten().unflatten()`.

## Examples

Example

The following code shows how a flattened JSON object is unflattened into the original nested JSON object.

```
#include <iostream>
#include <iomanip>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    // create JSON value
    json j_flattened =
    {
        {"/answer/everything", 42},
        {"/happy", true},
        {"/list/0", 1},
        {"/list/1", 0},
        {"/list/2", 2},
        {"/name", "Niels"},
        {"/nothing", nullptr},
        {"/object/currency", "USD"},
        {"/object/value", 42.99},
        {"/pi", 3.141}
    };

    // call unflatten()
    std::cout << std::setw(4) << j_flattened.unflatten() << '\n';
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
    "nothing": null,
    "object": {
        "currency": "USD",
        "value": 42.99
    },
    "pi": 3.141
}
```

## See also

- [flatten](https://json.nlohmann.me/api/basic_json/flatten/index.md) the reverse function

## Version history

- Added in version 2.0.0.
