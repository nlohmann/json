# Converting values

A `basic_json` value stores JSON data, but most of the time you want to move that data into ordinary C++ types (an
`#!cpp int`, a `#!cpp std::string`, a `#!cpp std::vector`, or one of your own structs) and back. This page describes how
these conversions work.

## Getting values out

The [`get`](../api/basic_json/get.md) function template returns a copy of the stored value converted to the requested
type:

```cpp
json j = R"({"name": "Mary", "age": 42, "hobbies": ["hiking", "reading"]})"_json;

auto name = j["name"].get<std::string>();               // "Mary"
auto age  = j["age"].get<int>();                        // 42
auto hobbies = j["hobbies"].get<std::vector<std::string>>();  // {"hiking", "reading"}
```

!!! note "Getting a string without quotes"

    A frequent point of confusion: use [`get`](../api/basic_json/get.md), **not** [`dump`](serialization.md), to read a
    string value. `#!cpp j["name"].get<std::string>()` yields `#!cpp Mary`, whereas `#!cpp j["name"].dump()` yields the
    JSON text `#!cpp "Mary"` (**with** quotes), because `dump` always produces a JSON text.

Alternatively, [`get_to`](../api/basic_json/get_to.md) writes into an existing variable and deduces the target type,
which avoids repeating it:

??? example

    ```cpp
    --8<-- "examples/get_to.cpp"
    ```

    Output:

    ```json
    --8<-- "examples/get_to.output"
    ```

The library already knows how to convert to and from the scalar types and the STL containers (such as
`#!cpp std::vector`, `#!cpp std::map`, `#!cpp std::array`, `#!cpp std::optional`, and many more). Converting a JSON
object back to a `#!cpp std::map` or a JSON array back to a `#!cpp std::vector` therefore works without any extra code:

```cpp
json j = {{"one", 1}, {"two", 2}};
auto m = j.get<std::map<std::string, int>>();  // {{"one", 1}, {"two", 2}}
```

## Implicit conversions

By default, a JSON value implicitly converts to a compatible C++ type, so the explicit `get` call can often be omitted:

```cpp
json j = "Hello";
std::string s = j;   // implicit conversion, same as j.get<std::string>()
```

Implicit conversions are convenient but can be surprising (for example, in overload resolution or with `auto`). They can
be disabled by defining [`JSON_USE_IMPLICIT_CONVERSIONS`](../api/macros/json_use_implicit_conversions.md) to `#!cpp 0`,
which forces the explicit `get` form and can catch unintended conversions at compile time.

!!! warning "Conversions do not range-check numbers"

    Just like C++ itself, the `get` family performs numeric conversions without range checks — retrieving a
    floating-point value as an integer truncates it, and narrowing conversions may overflow. See
    [number conversion](types/number_handling.md#number-conversion) for details and how to guard against it.

## Putting values in

The reverse direction works the same way: assigning or constructing a `json` from a C++ value converts it to JSON.

```cpp
std::vector<int> numbers = {1, 2, 3};
json j = numbers;   // [1,2,3]
```

## Your own types

The conversions above are built in for standard types. To make the same syntax work for **your own** types, provide
`to_json`/`from_json` functions (or use one of the convenience macros). This is described in detail on the
[arbitrary types conversions](arbitrary_types.md) page. Enums can be mapped to strings as described in
[specializing enum conversion](enum_conversion.md).

## See also

- [`get`](../api/basic_json/get.md) - get a copy converted to a given type
- [`get_to`](../api/basic_json/get_to.md) - convert into an existing variable
- [`get_ref`](../api/basic_json/get_ref.md) / [`get_ptr`](../api/basic_json/get_ptr.md) - access the stored value without copying
- [Arbitrary types conversions](arbitrary_types.md) - support your own types
- [`JSON_USE_IMPLICIT_CONVERSIONS`](../api/macros/json_use_implicit_conversions.md) - toggle implicit conversions
