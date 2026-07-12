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

`#!cpp std::pair` and `#!cpp std::tuple` are also supported, converting positionally to and from a JSON array:

```cpp
json j = {1.0, "hello", 42};
auto t = j.get<std::tuple<double, std::string, int>>();  // {1.0, "hello", 42}
```

!!! info "Extracting references into a tuple"

    A tuple type may also hold references (e.g. `#!cpp std::tuple<double&, std::string&>`) to avoid copying: `get`
    then returns a tuple of references pointing directly at the elements stored inside the `basic_json` array,
    rather than a tuple of copies:

    ```cpp
    json j = {1.0, "hello"};
    auto refs = j.get<std::tuple<double&, std::string&>>();
    std::get<1>(refs) = "world";  // modifies j[1] in place
    ```

    A referenced type must be one the library actually stores (or an arithmetic type it can convert to/from);
    otherwise this is a compile error.

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

!!! warning "std::optional direct construction from JSON null throws"

    Constructing or assigning `std::optional<T>` directly from a JSON value does not correctly produce
    `std::nullopt` for a JSON `null`:

    ```cpp
    json j_null;
    std::optional<std::string> opt = j_null;  // ❌ throws type_error 302
    ```

    This is due to C++ language rules: `std::optional<T>` has its own converting constructor that is chosen over
    `basic_json::operator T()` when both are viable. Use `get<std::optional<T>>()` or `get_to()` instead:

    ```cpp
    auto opt = j_null.get<std::optional<std::string>>();  // ✅ std::nullopt
    j_null.get_to(opt);                                     // ✅ std::nullopt
    ```

!!! warning "`static_cast` and `get<std::optional<T>>()` are not guaranteed equivalent"

    `operator ValueType()` (used by `static_cast` and implicit conversions) intentionally excludes
    `std::optional<T>` from delegating to `get<T>()`, to avoid a constructor ambiguity with
    `std::optional<T>`'s own converting constructor from `basic_json`. As a result,
    `static_cast<std::optional<T>>(json_value)` goes through `std::optional<T>`'s own converting
    constructor rather than through `get<std::optional<T>>()`, which can behave differently -- for example,
    with a custom `adl_serializer<std::optional<T>>` specialization. Prefer `get<std::optional<T>>()`/`get_to()`
    over `static_cast` for optional types.

!!! warning "Converting to a fixed-size `std::array` does not check length"

    Converting a JSON array to `#!cpp std::array<T, N>` does not check that the JSON array's size matches `N`:
    if the JSON array is longer, the extra elements are silently dropped; if it is shorter, the remaining
    `std::array` elements are left default-constructed. No exception is thrown in either case.

    ```cpp
    json j = {1, 2, 3, 4, 5};
    auto a = j.get<std::array<int, 3>>();  // {1, 2, 3} -- elements 4 and 5 silently dropped
    ```

## Omitting a field when serializing `std::optional`

By default, `to_json` for `std::optional<T>` writes either the value or `#!json null` -- there is no built-in way
to make a field disappear from the serialized object entirely when the `std::optional` is `std::nullopt`. Because
a specialization of `adl_serializer<std::optional<T>>` only controls how the *value* is converted (it cannot
prevent the containing object's `to_json` from inserting the key in the first place), omission has to be
implemented in the *containing* type's `to_json`:

```cpp
struct person {
    std::string name;
    std::optional<int> age;
};

void to_json(json& j, const person& p) {
    j = json{{"name", p.name}};
    if (p.age) {
        j["age"] = *p.age;  // key is only inserted when the optional has a value
    }
}
```

## Putting values in

The reverse direction works the same way: assigning or constructing a `json` from a C++ value converts it to JSON.

```cpp
std::vector<int> numbers = {1, 2, 3};
json j = numbers;   // [1,2,3]
```

!!! info "Constructing from a C++20 range view"

    A `json` array can also be constructed directly from a C++20 range view (`std::ranges::view`), such as the result
    of `std::views::filter` or `std::views::transform` -- no intermediate container is needed:

    ```cpp
    std::vector<int> nums{1, 2, 37, 42, 21};
    auto filtered = nums | std::views::filter([](int i) { return i > 10; });
    json j(filtered);   // [37,42,21]
    ```

    This requires [`JSON_HAS_RANGES`](../api/macros/json_has_ranges.md) to be enabled and is unavailable on MinGW due
    to incomplete C++20 ranges support there.

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
