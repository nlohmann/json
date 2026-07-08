# Creating JSON values

There are several ways to create a JSON value in memory. This page gives an overview; to read a value from JSON text instead, see [parsing](https://json.nlohmann.me/features/parsing/index.md).

## From C++ values

Any value of a supported C++ type can be assigned to or used to construct a `json`:

```
json j_number  = 42;
json j_float   = 3.141;
json j_string  = "Hello";
json j_boolean = true;
json j_null    = nullptr;
json j_vector  = std::vector<int>{1, 2, 3};   // array
```

See [converting values](https://json.nlohmann.me/features/conversions/index.md) for the full set of supported types.

## With initializer lists

Objects and arrays can be written concisely with brace-enclosed initializer lists:

```
// an array
json array = {1, 2, 3, 4};

// an object (a list of key/value pairs)
json object = {
    {"pi", 3.141},
    {"happy", true},
    {"name", "Niels"},
    {"nothing", nullptr},
    {"list", {1, 0, 2}},
    {"object", {{"currency", "USD"}, {"value", 42.99}}}
};
```

The library decides between an array and an object based on the content: a list whose elements are all two-element lists with a string as the first element is treated as an object, everything else as an array.

Ambiguous cases: `{}` vs. `[]`

Because the same `{}` syntax is used for both arrays and objects, some cases are ambiguous. To force a particular type, use the explicit factory functions [`json::array`](https://json.nlohmann.me/api/basic_json/array/index.md) and [`json::object`](https://json.nlohmann.me/api/basic_json/object/index.md):

```
json empty_array_explicit = json::array();               // []
json empty_object_explicit = json::object();             // {}

// a JSON array with one object, not an object with one member
json array_of_objects = json::array({{"key", "value"}}); // [{"key":"value"}]
```

Related to this, single-element brace initialization such as `json j{value};` wraps the element in a single-element **array** by default, and its behavior even differs between compilers. See the [FAQ](https://json.nlohmann.me/home/faq/#brace-initialization-yields-arrays) for details and the opt-in [`JSON_BRACE_INIT_COPY_SEMANTICS`](https://json.nlohmann.me/api/macros/json_brace_init_copy_semantics/index.md) macro.

## Building incrementally

A value can also be built up piece by piece. Accessing a non-existing object key or array index with [`operator[]`](https://json.nlohmann.me/features/element_access/unchecked_access/index.md) creates the element on the fly:

```
json j;                    // null
j["answer"]["everything"] = 42;   // becomes an object
j["list"] = {1, 0, 2};
j["list"].push_back(3);           // [1,0,2,3]
```

See [modifying values](https://json.nlohmann.me/features/modifying_values/index.md) for [`push_back`](https://json.nlohmann.me/api/basic_json/push_back/index.md), [`emplace`](https://json.nlohmann.me/api/basic_json/emplace/index.md), and related functions.

## With the `_json` literal

The `_json` [user-defined literal](https://json.nlohmann.me/api/operator_literal_json/index.md) parses a string at the call site and is a convenient way to write a JSON value inline:

Example

```
#include <iostream>
#include <iomanip>
#include <nlohmann/json.hpp>

using json = nlohmann::json;
using namespace nlohmann::literals;

int main()
{
    json j = R"( {"hello": "world", "answer": 42} )"_json;

    std::cout << std::setw(2) << j << '\n';
}
```

Output:

```
{
  "answer": 42,
  "hello": "world"
}
```

Note this **parses** the string, so `"42"_json` is the number `42`, whereas `json("42")` is the JSON string `"42"`.

## See also

- [`basic_json` constructors](https://json.nlohmann.me/api/basic_json/basic_json/index.md) - all ways to construct a value
- [`array`](https://json.nlohmann.me/api/basic_json/array/index.md) / [`object`](https://json.nlohmann.me/api/basic_json/object/index.md) - force array or object type
- [`operator""_json`](https://json.nlohmann.me/api/operator_literal_json/index.md) - the `_json` literal
- [Converting values](https://json.nlohmann.me/features/conversions/index.md) - which C++ types can be used
- [Parsing](https://json.nlohmann.me/features/parsing/index.md) - create a value from JSON text
