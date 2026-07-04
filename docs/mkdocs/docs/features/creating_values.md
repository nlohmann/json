# Creating JSON values

There are several ways to create a JSON value in memory. This page gives an overview; to read a value from JSON text
instead, see [parsing](parsing/index.md).

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
    --8<-- "examples/operator_literal_json.cpp"
    ```

    Output:

    ```json
    --8<-- "examples/operator_literal_json.output"
    ```

Note this **parses** the string, so `#!cpp "42"_json` is the number `#!cpp 42`, whereas `#!cpp json("42")` is the JSON
string `#!json "42"`.

## See also

- [`basic_json` constructors](../api/basic_json/basic_json.md) - all ways to construct a value
- [`array`](../api/basic_json/array.md) / [`object`](../api/basic_json/object.md) - force array or object type
- [`operator""_json`](../api/operator_literal_json.md) - the `_json` literal
- [Converting values](conversions.md) - which C++ types can be used
- [Parsing](parsing/index.md) - create a value from JSON text
