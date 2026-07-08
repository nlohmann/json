# nlohmann::basic_json::operator ValueType

```
template<typename ValueType>
JSON_EXPLICIT operator ValueType() const;
```

Implicit type conversion between the JSON value and a compatible value. The call is realized by calling [`get()`](https://json.nlohmann.me/api/basic_json/get/index.md). See [Notes](#notes) for the meaning of `JSON_EXPLICIT`.

## Template parameters

`ValueType` : the value type to return

## Return value

copy of the JSON value, converted to `ValueType`

## Exceptions

Depends on what `json_serializer<ValueType>` `from_json()` method throws

## Complexity

Linear in the size of the JSON value.

## Notes

Definition of `JSON_EXPLICIT`

By default `JSON_EXPLICIT` is defined to the empty string, so the signature is:

```
template<typename ValueType>
operator ValueType() const;
```

If [`JSON_USE_IMPLICIT_CONVERSIONS`](https://json.nlohmann.me/api/macros/json_use_implicit_conversions/index.md) is set to `0`, `JSON_EXPLICIT` is defined to `explicit`:

```
template<typename ValueType>
explicit operator ValueType() const;
```

That is, implicit conversions can be switched off by defining [`JSON_USE_IMPLICIT_CONVERSIONS`](https://json.nlohmann.me/api/macros/json_use_implicit_conversions/index.md) to `0`.

Future behavior change

Implicit conversions will be switched off by default in the next major release of the library. That is, `JSON_EXPLICIT` will be set to `explicit` by default.

You can prepare existing code by already defining [`JSON_USE_IMPLICIT_CONVERSIONS`](https://json.nlohmann.me/api/macros/json_use_implicit_conversions/index.md) to `0` and replace any implicit conversions with calls to [`get`](https://json.nlohmann.me/api/basic_json/get/index.md).

## Examples

Example

The example below shows several conversions from JSON values to other types. There are a few things to note: (1) Floating-point numbers can be converted to integers, (2) A JSON array can be converted to a standard `std::vector<short>`, (3) A JSON object can be converted to C++ associative containers such as `std::unordered_map<std::string, json>`.

```
#include <iostream>
#include <unordered_map>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    // create a JSON value with different types
    json json_types =
    {
        {"boolean", true},
        {
            "number", {
                {"integer", 42},
                {"floating-point", 17.23}
            }
        },
        {"string", "Hello, world!"},
        {"array", {1, 2, 3, 4, 5}},
        {"null", nullptr}
    };

    // use implicit conversions
    bool v1 = json_types["boolean"];
    int v2 = json_types["number"]["integer"];
    short v3 = json_types["number"]["integer"];
    float v4 = json_types["number"]["floating-point"];
    int v5 = json_types["number"]["floating-point"];
    std::string v6 = json_types["string"];
    std::vector<short> v7 = json_types["array"];
    std::unordered_map<std::string, json> v8 = json_types;

    // print the conversion results
    std::cout << v1 << '\n';
    std::cout << v2 << ' ' << v3 << '\n';
    std::cout << v4 << ' ' << v5 << '\n';
    std::cout << v6 << '\n';

    for (auto i : v7)
    {
        std::cout << i << ' ';
    }
    std::cout << "\n\n";

    for (auto i : v8)
    {
        std::cout << i.first << ": " << i.second << '\n';
    }

    // example for an exception
    try
    {
        bool v1 = json_types["string"];
    }
    catch (const json::type_error& e)
    {
        std::cout << e.what() << '\n';
    }
}
```

Output:

```
1
42 42
17.23 17
Hello, world!
1 2 3 4 5 

string: "Hello, world!"
number: {"floating-point":17.23,"integer":42}
null: null
boolean: true
array: [1,2,3,4,5]
[json.exception.type_error.302] type must be boolean, but is string
```

## See also

- [get](https://json.nlohmann.me/api/basic_json/get/index.md) get a value (explicit conversion)
- [Converting values](https://json.nlohmann.me/features/conversions/index.md) - the type conversions article

## Version history

- Since version 1.0.0.
- Macros `JSON_EXPLICIT`/[`JSON_USE_IMPLICIT_CONVERSIONS`](https://json.nlohmann.me/api/macros/json_use_implicit_conversions/index.md) added in version 3.9.0.
