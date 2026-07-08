# nlohmann::basic_json::get_to

```
template<typename ValueType>
ValueType& get_to(ValueType& v) const noexcept(
    noexcept(JSONSerializer<ValueType>::from_json(
        std::declval<const basic_json_t&>(), v)));
```

Explicit type conversion between the JSON value and a compatible value. The value is filled into the input parameter by calling the `json_serializer<ValueType>` `from_json()` method.

The function is equivalent to executing

```
ValueType v;
JSONSerializer<ValueType>::from_json(*this, v);
```

This overload is chosen if:

- `ValueType` is not `basic_json`,
- `json_serializer<ValueType>` has a `from_json()` method of the form `void from_json(const basic_json&, ValueType&)`

## Template parameters

`ValueType` : the value type to return

## Return value

the input parameter, allowing chaining calls

## Exceptions

Depends on what `json_serializer<ValueType>` `from_json()` method throws

## Complexity

Depends on the `json_serializer<ValueType>::from_json()` implementation.

## Examples

Example

The example below shows several conversions from JSON values to other types. There a few things to note: (1) Floating-point numbers can be converted to integers, (2) A JSON array can be converted to a standard `std::vector<short>`, (3) A JSON object can be converted to C++ associative containers such as `#cpp std::unordered_map<std::string, json>`.

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

## See also

- [get](https://json.nlohmann.me/api/basic_json/get/index.md) get a value (explicit conversion)
- [get_ref](https://json.nlohmann.me/api/basic_json/get_ref/index.md) get a reference to the stored value
- [get_ptr](https://json.nlohmann.me/api/basic_json/get_ptr/index.md) get a pointer to the stored value
- [Converting values](https://json.nlohmann.me/features/conversions/index.md) - the type conversions article

## Version history

- Since version 3.3.0.
