# nlohmann::basic_json::get

```
// (1)
template<typename ValueType>
ValueType get() const noexcept(
    noexcept(JSONSerializer<ValueType>::from_json(
        std::declval<const basic_json_t&>(), std::declval<ValueType&>())));

// (2)
template<typename BasicJsonType>
BasicJsonType get() const;

// (3)
template<typename PointerType>
PointerType get_ptr();

template<typename PointerType>
constexpr const PointerType get_ptr() const noexcept;
```

1. Explicit type conversion between the JSON value and a compatible value which is [CopyConstructible](https://en.cppreference.com/w/cpp/named_req/CopyConstructible) and [DefaultConstructible](https://en.cppreference.com/w/cpp/named_req/DefaultConstructible). The value is converted by calling the `json_serializer<ValueType>` `from_json()` method.

   The function is equivalent to executing

   ```
   ValueType ret;
   JSONSerializer<ValueType>::from_json(*this, ret);
   return ret;
   ```

   This overload is chosen if:

   - `ValueType` is not `basic_json`,
   - `json_serializer<ValueType>` has a `from_json()` method of the form `void from_json(const basic_json&, ValueType&)`, and
   - `json_serializer<ValueType>` does not have a `from_json()` method of the form `ValueType from_json(const basic_json&)`

   If the type is **not** [CopyConstructible](https://en.cppreference.com/w/cpp/named_req/CopyConstructible) and **not** [DefaultConstructible](https://en.cppreference.com/w/cpp/named_req/DefaultConstructible), the value is converted by calling the `json_serializer<ValueType>` `from_json()` method.

   The function is then equivalent to executing

   ```
   return JSONSerializer<ValueTypeCV>::from_json(*this);
   ```

   This overload is chosen if:

   - `ValueType` is not `basic_json` and
   - `json_serializer<ValueType>` has a `from_json()` method of the form `ValueType from_json(const basic_json&)`

   If `json_serializer<ValueType>` has both overloads of `from_json()`, the latter one is chosen.

1. Overload for `basic_json` specializations. The function is equivalent to executing

   ```
   return *this;
   ```

1. Explicit pointer access to the internally stored JSON value. No copies are made.

## Template parameters

`ValueType` : the value type to return

`BasicJsonType` : a specialization of `basic_json`

`PointerType` : pointer type; must be a pointer to [`array_t`](https://json.nlohmann.me/api/basic_json/array_t/index.md), [`object_t`](https://json.nlohmann.me/api/basic_json/object_t/index.md), [`string_t`](https://json.nlohmann.me/api/basic_json/string_t/index.md), [`boolean_t`](https://json.nlohmann.me/api/basic_json/boolean_t/index.md), [`number_integer_t`](https://json.nlohmann.me/api/basic_json/number_integer_t/index.md), or [`number_unsigned_t`](https://json.nlohmann.me/api/basic_json/number_unsigned_t/index.md), [`number_float_t`](https://json.nlohmann.me/api/basic_json/number_float_t/index.md), or [`binary_t`](https://json.nlohmann.me/api/basic_json/binary_t/index.md). Other types will not compile.

## Return value

1. copy of the JSON value, converted to `ValueType`
1. a copy of `*this`, converted into `BasicJsonType`
1. pointer to the internally stored JSON value if the requested pointer type fits to the JSON value; `nullptr` otherwise

## Exceptions

Depends on what `json_serializer<ValueType>` `from_json()` method throws

## Complexity

Depends on the `json_serializer<ValueType>::from_json()` implementation for overloads (1) and (2); constant for overload (3).

## Notes

Undefined behavior for pointers

Writing data to the pointee (overload 3) of the result yields an undefined state.

Undefined behavior for numeric conversions

Conversions between numeric types are performed by the corresponding `from_json()` implementation using the target C++ type. When converting between numeric types, the library does not check whether the source value is representable by the target type.

If the source value is outside the range of the target type, the behavior is the same as the corresponding C++ conversion. In particular, converting a floating-point value to an integer type that cannot represent the value results in undefined behavior.

See [Number conversion](https://json.nlohmann.me/features/types/number_handling/#number-conversion) for more information.

`std::optional` conversions

Prior to version 3.13.0, `get<std::optional<T>>()` (and other conversions to `std::optional<T>`) failed to compile in every configuration, due to an internal implementation bug that made the `from_json` overload for `std::optional` unreachable regardless of the [`JSON_USE_IMPLICIT_CONVERSIONS`](https://json.nlohmann.me/api/macros/json_use_implicit_conversions/index.md) setting. This has been fixed.

## Examples

Example

The example below shows several conversions from JSON values to other types. There a few things to note: (1) Floating-point numbers can be converted to integers, (2) A JSON array can be converted to a standard `std::vector<short>`, (3) A JSON object can be converted to C++ associative containers such as `std::unordered_map<std::string, json>`.

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

    // use explicit conversions
    auto v1 = json_types["boolean"].get<bool>();
    auto v2 = json_types["number"]["integer"].get<int>();
    auto v3 = json_types["number"]["integer"].get<short>();
    auto v4 = json_types["number"]["floating-point"].get<float>();
    auto v5 = json_types["number"]["floating-point"].get<int>();
    auto v6 = json_types["string"].get<std::string>();
    auto v7 = json_types["array"].get<std::vector<short>>();
    auto v8 = json_types.get<std::unordered_map<std::string, json>>();

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

Example

The example below shows how pointers to internal values of a JSON value can be requested. Note that no type conversions are made and a `#cpp nullptr` is returned if the value and the requested pointer type does not match.

```
#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    // create a JSON number
    json value = 17;

    // explicitly getting pointers
    auto p1 = value.get<const json::number_integer_t*>();
    auto p2 = value.get<json::number_integer_t*>();
    auto p3 = value.get<json::number_integer_t* const>();
    auto p4 = value.get<const json::number_integer_t* const>();
    auto p5 = value.get<json::number_float_t*>();

    // print the pointees
    std::cout << *p1 << ' ' << *p2 << ' ' << *p3 << ' ' << *p4 << '\n';
    std::cout << std::boolalpha << (p5 == nullptr) << '\n';
}
```

Output:

```
17 17 17 17
true
```

## See also

- [get_to](https://json.nlohmann.me/api/basic_json/get_to/index.md) convert and write into a passed value
- [get_ptr](https://json.nlohmann.me/api/basic_json/get_ptr/index.md) get a pointer to the stored value
- [get_ref](https://json.nlohmann.me/api/basic_json/get_ref/index.md) get a reference to the stored value
- [operator ValueType](https://json.nlohmann.me/api/basic_json/operator_ValueType/index.md) get a value via implicit conversion
- [Converting values](https://json.nlohmann.me/features/conversions/index.md) - the type conversions article

## Version history

1. Since version 2.1.0.
1. Since version 2.1.0. Extended to work with other specializations of `basic_json` in version 3.2.0.
1. Since version 1.0.0.
