# Creating JSON values

There are several ways to create a JSON value in memory. This page gives an overview; to read a value from JSON text
instead, see [parsing](parsing/index.md). A JSON text can also be parsed into a
[document](../api/basic_json_document/index.md) and read through a [view](../api/basic_json_view/index.md) instead of
into a value; see [Zero-copy JSON views](json_view.md).

## From C++ values

Any value of a supported C++ type can be assigned to or used to construct a `json`:

```cpp
json j_number  = 42;
json j_float   = 3.141;
json j_string  = "Hello";
json j_boolean = true;
json j_null    = nullptr;
json j_vector  = std::vector<int>{1, 2, 3};   // array
```

See [converting values](conversions.md) for the full set of supported types.

## With initializer lists

Objects and arrays can be written concisely with brace-enclosed initializer lists:

```cpp
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

The library decides between an array and an object based on the content: a list whose elements are all two-element lists
with a string as the first element is treated as an object, everything else as an array.

!!! warning "Ambiguous cases: `#!cpp {}` vs. `#!cpp []`"

    Because the same `#!cpp {}` syntax is used for both arrays and objects, some cases are ambiguous. To force a
    particular type, use the explicit factory functions [`json::array`](../api/basic_json/array.md) and
    [`json::object`](../api/basic_json/object.md):

    ```cpp
    json empty_array_explicit = json::array();               // []
    json empty_object_explicit = json::object();             // {}

    // a JSON array with one object, not an object with one member
    json array_of_objects = json::array({{"key", "value"}}); // [{"key":"value"}]
    ```

    Related to this, single-element brace initialization such as `#!cpp json j{value};` wraps the element in a
    single-element **array** by default, and its behavior even differs between compilers. See the
    [FAQ](../home/faq.md#brace-initialization-yields-arrays) for details and the opt-in
    [`JSON_BRACE_INIT_COPY_SEMANTICS`](../api/macros/json_brace_init_copy_semantics.md) macro.

### What does this produce?

The following table shows how some common spellings are interpreted. When in doubt, use `#!cpp json::array()`,
`#!cpp json::object()`, or the `#!cpp json(value)` form with parentheses.

| code                                            | result                       | note                                         |
|-------------------------------------------------|------------------------------|----------------------------------------------|
| `#!cpp json j = {};` / `#!cpp json j{};`        | `#!json null`                | use `json::object()` or `json::array()`      |
| `#!cpp json j = json::object();`                | `#!json {}`                  |                                              |
| `#!cpp json j = json::array();`                 | `#!json []`                  |                                              |
| `#!cpp json j(true);`                           | `#!json true`                | parentheses create the value itself          |
| `#!cpp json j = {true};`                        | `#!json [true]`              | braces create a one-element array (`#!cpp json j{true};` depends on the compiler, see the [FAQ](../home/faq.md#brace-initialization-yields-arrays)) |
| `#!cpp json j = {{"a", 1}};`                    | `#!json {"a":1}`             | all elements are `[string, value]` pairs: object |
| `#!cpp json j = {{"a", 1}, {"b"}};`             | `#!json [["a",1],["b"]]`     | one element is not a pair: array             |
| `#!cpp json j = {{"a", 1}, 2};`                 | `#!json [["a",1],2]`         | a plain value among pairs: array             |
| `#!cpp json j = {{"a", 1, 2}};`                 | `#!json [["a",1,2]]`         | a three-element list is not a pair: array    |
| `#!cpp json j = "{\"a\":1}";`                   | `#!json "{\"a\":1}"`           | a string **value**; it is not parsed         |
| `#!cpp json j = json::parse("{\"a\":1}");`      | `#!json {"a":1}`             | parse text with `parse` or `_json`           |

## Building incrementally

A value can also be built up piece by piece. Accessing a non-existing object key or array index with
[`operator[]`](element_access/unchecked_access.md) creates the element on the fly:

```cpp
json j;                    // null
j["answer"]["everything"] = 42;   // becomes an object
j["list"] = {1, 0, 2};
j["list"].push_back(3);           // [1,0,2,3]
```

See [modifying values](modifying_values.md) for [`push_back`](../api/basic_json/push_back.md),
[`emplace`](../api/basic_json/emplace.md), and related functions.

## With the `_json` literal

The `_json` [user-defined literal](../api/operator_literal_json.md) parses a string at the call site and is a
convenient way to write a JSON value inline:

??? example

    ```cpp
    #include <iostream>
    #include <iomanip>
    #include <nlohmann/json.hpp>
    
    using nlohmann::json;
    using namespace nlohmann::literals;
    
    int main()
    {
        json j = R"( {"hello": "world", "answer": 42} )"_json;
    
        std::cout << std::setw(2) << j << '\n';
    }
    
    ```

    Output:

    ```json
    {
      "answer": 42,
      "hello": "world"
    }
    
    ```

Note this **parses** the string, so `#!cpp "42"_json` is the number `#!cpp 42`, whereas `#!cpp json("42")` is the JSON
string `#!json "42"`.

## See also

- [`basic_json` constructors](../api/basic_json/basic_json.md) - all ways to construct a value
- [`array`](../api/basic_json/array.md) - / [`object`](../api/basic_json/object.md) - force array or object type
- [`operator""_json`](../api/operator_literal_json.md) - the `_json` literal
- [Converting values](conversions.md) - which C++ types can be used
- [Parsing](parsing/index.md) - create a value from JSON text
- [Zero-copy JSON views](json_view.md) - create a document and a view from JSON text instead of a value
- [`basic_json`](../api/basic_json/index.md) - the class template and its member functions
- [Types](types/index.md) - the JSON value types
- [`JSON_BRACE_INIT_COPY_SEMANTICS`](../api/macros/json_brace_init_copy_semantics.md) - change how a single braced value is interpreted
- [`operator=`](../api/basic_json/operator=.md) - assign a new value

