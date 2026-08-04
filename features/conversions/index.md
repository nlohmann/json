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

`std::pair` and `std::tuple` are also supported, converting positionally to and from a JSON array:

```
json j = {1.0, "hello", 42};
auto t = j.get<std::tuple<double, std::string, int>>();  // {1.0, "hello", 42}
```

Extracting references into a tuple

A tuple type may also hold references (e.g. `std::tuple<double&, std::string&>`) to avoid copying: `get` then returns a tuple of references pointing directly at the elements stored inside the `basic_json` array, rather than a tuple of copies:

```
json j = {1.0, "hello"};
auto refs = j.get<std::tuple<double&, std::string&>>();
std::get<1>(refs) = "world";  // modifies j[1] in place
```

A referenced element must name the type the library actually *stores* — one of [`boolean_t`](https://json.nlohmann.me/api/basic_json/boolean_t/index.md), [`number_integer_t`](https://json.nlohmann.me/api/basic_json/number_integer_t/index.md), [`number_unsigned_t`](https://json.nlohmann.me/api/basic_json/number_unsigned_t/index.md), [`number_float_t`](https://json.nlohmann.me/api/basic_json/number_float_t/index.md), [`string_t`](https://json.nlohmann.me/api/basic_json/string_t/index.md), [`binary_t`](https://json.nlohmann.me/api/basic_json/binary_t/index.md), [`array_t`](https://json.nlohmann.me/api/basic_json/array_t/index.md), or [`object_t`](https://json.nlohmann.me/api/basic_json/object_t/index.md). There is nothing else to refer to, so a reference to any other type is a compile error even when a conversion would exist: `std::tuple<int&>` is rejected, because the library stores a `number_integer_t` (`std::int64_t` by default) and not an `int`. This restriction applies only to reference elements — a plain `std::tuple<int>` converts by value as usual.

## Implicit conversions

By default, a JSON value implicitly converts to a compatible C++ type, so the explicit `get` call can often be omitted:

```
json j = "Hello";
std::string s = j;   // implicit conversion, same as j.get<std::string>()
```

Implicit conversions are convenient but can be surprising (for example, in overload resolution or with `auto`). They can be disabled by defining [`JSON_USE_IMPLICIT_CONVERSIONS`](https://json.nlohmann.me/api/macros/json_use_implicit_conversions/index.md) to `0`, which forces the explicit `get` form and can catch unintended conversions at compile time.

Conversions do not range-check numbers

Just like C++ itself, the `get` family performs numeric conversions without range checks — retrieving a floating-point value as an integer truncates it, and narrowing conversions may overflow. See [number conversion](https://json.nlohmann.me/features/types/number_handling/#number-conversion) for details and how to guard against it.

std::optional direct construction from JSON null throws

Constructing or assigning `std::optional<T>` directly from a JSON value does not correctly produce `std::nullopt` for a JSON `null`:

```
json j_null;
std::optional<std::string> opt = j_null;  // ❌ throws type_error 302
```

This is due to C++ language rules: `std::optional<T>` has its own converting constructor that is chosen over `basic_json::operator T()` when both are viable. Use `get<std::optional<T>>()` or `get_to()` instead:

```
auto opt = j_null.get<std::optional<std::string>>();  // ✅ std::nullopt
j_null.get_to(opt);                                     // ✅ std::nullopt
```

`static_cast` and `get<std::optional<T>>()` are not guaranteed equivalent

`operator ValueType()` (used by `static_cast` and implicit conversions) intentionally excludes `std::optional<T>` from delegating to `get<T>()`, to avoid a constructor ambiguity with `std::optional<T>`'s own converting constructor from `basic_json`. As a result, `static_cast<std::optional<T>>(json_value)` goes through `std::optional<T>`'s own converting constructor rather than through `get<std::optional<T>>()`, which can behave differently -- for example, with a custom `adl_serializer<std::optional<T>>` specialization. Prefer `get<std::optional<T>>()`/`get_to()` over `static_cast` for optional types.

Converting to a fixed-size destination does not check the array size

Some destination types have a size that is fixed by their C++ type rather than by the JSON value: `std::pair<A, B>`, `std::tuple<Ts...>`, `std::array<T, N>`, C arrays `T[N]`, and `std::map`/`std::unordered_map` with a non-string key type (which is read from an array of two-element arrays). All of them read exactly as many elements as they need via [`at`](https://json.nlohmann.me/api/basic_json/at/index.md) and **never compare the JSON array's size to that number**. The two mismatch directions therefore behave differently:

- The JSON array has **too many** elements: the surplus is **silently discarded**, and no exception is thrown.
- The JSON array has **too few** elements: `at` throws [`out_of_range.401`](https://json.nlohmann.me/home/exceptions/#jsonexceptionout_of_range401) for the first missing index -- an out-of-range error, not a [`type_error`](https://json.nlohmann.me/home/exceptions/#type-errors), even though the cause is a shape mismatch.

```
json j = {1, 2, 3, 4, 5};

auto a = j.get<std::array<int, 3>>();       // {1, 2, 3} -- elements 4 and 5 silently dropped
auto p = j.get<std::pair<int, int>>();      // (1, 2)    -- elements 3, 4, and 5 silently dropped

json k = {1};
auto q = k.get<std::pair<int, int>>();      // ❌ throws out_of_range.401
```

If a size mismatch is an error in your application, check the size yourself before converting.

## Omitting a field when serializing `std::optional`

By default, `to_json` for `std::optional<T>` writes either the value or `null` -- there is no built-in way to make a field disappear from the serialized object entirely when the `std::optional` is `std::nullopt`. Because a specialization of `adl_serializer<std::optional<T>>` only controls how the *value* is converted (it cannot prevent the containing object's `to_json` from inserting the key in the first place), omission has to be implemented in the *containing* type's `to_json`:

```
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

```
std::vector<int> numbers = {1, 2, 3};
json j = numbers;   // [1,2,3]
```

Constructing from a C++20 range view

A `json` array can also be constructed directly from a C++20 range view (`std::ranges::view`), such as the result of `std::views::filter` or `std::views::transform` -- no intermediate container is needed:

```
std::vector<int> nums{1, 2, 37, 42, 21};
auto filtered = nums | std::views::filter([](int i) { return i > 10; });
json j(filtered);   // [37,42,21]
```

This requires [`JSON_HAS_RANGES`](https://json.nlohmann.me/api/macros/json_has_ranges/index.md) to be enabled and is unavailable on MinGW due to incomplete C++20 ranges support there.

## Your own types

The conversions above are built in for standard types. To make the same syntax work for **your own** types, provide `to_json`/`from_json` functions (or use one of the convenience macros). This is described in detail on the [arbitrary types conversions](https://json.nlohmann.me/features/arbitrary_types/index.md) page. Enums can be mapped to strings as described in [specializing enum conversion](https://json.nlohmann.me/features/enum_conversion/index.md).

## See also

- [`get`](https://json.nlohmann.me/api/basic_json/get/index.md) - get a copy converted to a given type
- [`get_to`](https://json.nlohmann.me/api/basic_json/get_to/index.md) - convert into an existing variable
- [`get_ref`](https://json.nlohmann.me/api/basic_json/get_ref/index.md) / [`get_ptr`](https://json.nlohmann.me/api/basic_json/get_ptr/index.md) - access the stored value without copying
- [Arbitrary types conversions](https://json.nlohmann.me/features/arbitrary_types/index.md) - support your own types
- [`JSON_USE_IMPLICIT_CONVERSIONS`](https://json.nlohmann.me/api/macros/json_use_implicit_conversions/index.md) - toggle implicit conversions
