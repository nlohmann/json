# Converting values

A `basic_json` value stores JSON data, but most of the time you want to move that data into ordinary C++ types (an `int`, a `std::string`, a `std::vector`, or one of your own structs) and back. This page describes how these conversions work.

## Getting values out

The [`get`](https://json.nlohmann.me/api/basic_json/get/index.md) function template returns a copy of the stored value converted to the requested type:

```
json j = R"({"name": "Mary", "age": 42, "hobbies": ["hiking", "reading"]})"_json;

auto name = j["name"].get<std::string>();               // "Mary"
auto age  = j["age"].get<int>();                        // 42
auto hobbies = j["hobbies"].get<std::vector<std::string>>();  // {"hiking", "reading"}
```

Getting a string without quotes

A frequent point of confusion: use [`get`](https://json.nlohmann.me/api/basic_json/get/index.md), **not** [`dump`](https://json.nlohmann.me/features/serialization/index.md), to read a string value. `j["name"].get<std::string>()` yields `Mary`, whereas `j["name"].dump()` yields the JSON text `"Mary"` (**with** quotes), because `dump` always produces a JSON text.

Alternatively, [`get_to`](https://json.nlohmann.me/api/basic_json/get_to/index.md) writes into an existing variable and deduces the target type, which avoids repeating it:

Example

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

    bool v1;
    int v2;
    short v3;
    float v4;
    int v5;
    std::string v6;
    std::vector<short> v7;
    std::unordered_map<std::string, json> v8;

    // use explicit conversions
    json_types["boolean"].get_to(v1);
    json_types["number"]["integer"].get_to(v2);
    json_types["number"]["integer"].get_to(v3);
    json_types["number"]["floating-point"].get_to(v4);
    json_types["number"]["floating-point"].get_to(v5);
    json_types["string"].get_to(v6);
    json_types["array"].get_to(v7);
    json_types.get_to(v8);

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
```

The library already knows how to convert to and from the scalar types and the STL containers (such as `std::vector`, `std::map`, `std::array`, `std::optional`, and many more). Converting a JSON object back to a `std::map` or a JSON array back to a `std::vector` therefore works without any extra code:

```
json j = {{"one", 1}, {"two", 2}};
auto m = j.get<std::map<std::string, int>>();  // {{"one", 1}, {"two", 2}}
```

## Implicit conversions

By default, a JSON value implicitly converts to a compatible C++ type, so the explicit `get` call can often be omitted:

```
json j = "Hello";
std::string s = j;   // implicit conversion, same as j.get<std::string>()
```

Implicit conversions are convenient but can be surprising (for example, in overload resolution or with `auto`). They can be disabled by defining [`JSON_USE_IMPLICIT_CONVERSIONS`](https://json.nlohmann.me/api/macros/json_use_implicit_conversions/index.md) to `0`, which forces the explicit `get` form and can catch unintended conversions at compile time.

Conversions do not range-check numbers

Just like C++ itself, the `get` family performs numeric conversions without range checks — retrieving a floating-point value as an integer truncates it, and narrowing conversions may overflow. See [number conversion](https://json.nlohmann.me/features/types/number_handling/#number-conversion) for details and how to guard against it.

## Putting values in

The reverse direction works the same way: assigning or constructing a `json` from a C++ value converts it to JSON.

```
std::vector<int> numbers = {1, 2, 3};
json j = numbers;   // [1,2,3]
```

## Your own types

The conversions above are built in for standard types. To make the same syntax work for **your own** types, provide `to_json`/`from_json` functions (or use one of the convenience macros). This is described in detail on the [arbitrary types conversions](https://json.nlohmann.me/features/arbitrary_types/index.md) page. Enums can be mapped to strings as described in [specializing enum conversion](https://json.nlohmann.me/features/enum_conversion/index.md).

## See also

- [`get`](https://json.nlohmann.me/api/basic_json/get/index.md) - get a copy converted to a given type
- [`get_to`](https://json.nlohmann.me/api/basic_json/get_to/index.md) - convert into an existing variable
- [`get_ref`](https://json.nlohmann.me/api/basic_json/get_ref/index.md) / [`get_ptr`](https://json.nlohmann.me/api/basic_json/get_ptr/index.md) - access the stored value without copying
- [Arbitrary types conversions](https://json.nlohmann.me/features/arbitrary_types/index.md) - support your own types
- [`JSON_USE_IMPLICIT_CONVERSIONS`](https://json.nlohmann.me/api/macros/json_use_implicit_conversions/index.md) - toggle implicit conversions
