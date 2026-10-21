# nlohmann::basic_json_view::get

```
template<typename T>
T get() const;
```

Converts the value to `T`.

For the types below, the conversion works directly on the flat index -- no `BasicJsonType` value is built for it:

- `bool`
- arithmetic types other than `bool` (for a boolean, `0`/`1`, exactly as for [`BasicJsonType::get<T>()`](https://json.nlohmann.me/api/basic_json/get/index.md))
- `std::nullptr_t`
- `std::basic_string<char, Traits, Alloc>` (including `string_t`) -- a copy of the string
- [`string_view_t`](https://json.nlohmann.me/api/basic_json_view/#member-types) -- **no copy**: the returned view points into the document's [`source()`](https://json.nlohmann.me/api/basic_json_document/source/index.md) text, or, for a string that contains escape sequences, into the document's own buffer of decoded strings (see [`get_string()`](https://json.nlohmann.me/api/basic_json_view/get_string/index.md))
- `BasicJsonType` -- equivalent to [`materialize()`](https://json.nlohmann.me/api/basic_json_view/materialize/index.md)
- `basic_json_view` -- returns `*this`
- `std::vector<U, A>` -- from an array, element by element, each converted with `get<U>()`; `std::vector<basic_json_view>` keeps a view of every element instead of a value
- `std::map<K, V, C, A>` and `std::unordered_map<K, V, H, E, A>`, if `K` is constructible from a `(const char*, std::size_t)` pair -- from an object, member by member, each value converted with `get<V>()`; with a repeated key, the *last* value is kept, as [`BasicJsonType::parse()`](https://json.nlohmann.me/api/basic_json/parse/index.md) (and [`materialize()`](https://json.nlohmann.me/api/basic_json_view/materialize/index.md)) does; `std::map<std::string, basic_json_view>` keeps views of the members instead of values

Every other `T` -- `std::list`, `std::pair`, `std::array`, enumerations, user types with a `from_json()`, ... -- is converted by `materialize().get<T>()`: the subtree is built into a real `BasicJsonType` value first (as [`BasicJsonType::parse()`](https://json.nlohmann.me/api/basic_json/parse/index.md) would), and converted from there exactly as [`BasicJsonType::get<T>()`](https://json.nlohmann.me/api/basic_json/get/index.md) would convert it.

## Template parameters

`T` : the type to convert the value to

## Return value

the value, converted to `T`

## Exception safety

Strong guarantee: there are no changes to the view or the document it refers to.

## Exceptions

- For the directly-converted types listed above (other than `BasicJsonType` and `basic_json_view`, which never throw): throws [`type_error.302`](https://json.nlohmann.me/home/exceptions/#jsonexceptiontype_error302) if the value's type does not match `T` -- the same exception, with the same message, that [`BasicJsonType::get<T>()`](https://json.nlohmann.me/api/basic_json/get/index.md) throws for the same JSON type and `T`.
- For `std::vector<U, A>`: throws `type_error.302` if the value is not an array; otherwise, whatever converting an element to `U` throws.
- For `std::map`/`std::unordered_map`: throws `type_error.302` if the value is not an object; otherwise, whatever converting a member to the mapped type throws.
- For every other `T`: whatever [`materialize().get<T>()`](https://json.nlohmann.me/api/basic_json/get/index.md) throws -- typically `type_error.302`, or whatever a user-provided `from_json()` throws.

None of the exceptions thrown directly by this function (the first three bullets above) carry a [`JSON_DIAGNOSTICS`](https://json.nlohmann.me/api/macros/json_diagnostics/index.md) path: the view has no `BasicJsonType` value to point at. An exception thrown while converting through `materialize()` (the last bullet) is different: it is thrown by a real `BasicJsonType` value, so it **does** carry a `JSON_DIAGNOSTICS` path if `BasicJsonType` was built with it enabled. That path is relative to the root of the view's subtree, because `materialize()` builds only the subtree (with parent pointers): it is empty if the failing value is the subtree's root itself, and it never is the path within the whole document.

## Complexity

- `bool`, arithmetic types, `std::nullptr_t`, [`string_view_t`](https://json.nlohmann.me/api/basic_json_view/#member-types), `basic_json_view`: constant.
- `std::basic_string<char, Traits, Alloc>`: constant, plus one allocation and a copy of the string's bytes.
- `BasicJsonType`: linear in the size of the subtree, see [`materialize()`](https://json.nlohmann.me/api/basic_json_view/materialize/index.md).
- `std::vector<U, A>`: linear in the number of elements, times the complexity of converting one element to `U`.
- `std::map`/`std::unordered_map`: linear in the number of members for walking them, plus the container's own insertion cost per member (logarithmic for `std::map`, amortized constant for `std::unordered_map`), times the complexity of converting one member to the mapped type.
- every other `T`: the cost of [`materialize()`](https://json.nlohmann.me/api/basic_json_view/materialize/index.md) and of destroying the `BasicJsonType` value afterwards, plus that of [`BasicJsonType::get<T>()`](https://json.nlohmann.me/api/basic_json/get/index.md).

## Notes

Floating-point values

A floating-point `T` is converted from the same digits the lexer would see during `BasicJsonType::parse()`, using the same conversion, so the result is bit-for-bit identical to `BasicJsonType::parse(text).get<T>()` for the same source text.

Duplicate keys

`std::map`/`std::unordered_map` conversions keep the *last* value of a repeated key, like [`materialize()`](https://json.nlohmann.me/api/basic_json_view/materialize/index.md) and [`BasicJsonType::parse()`](https://json.nlohmann.me/api/basic_json/parse/index.md) do. This is the opposite of [`operator[]`](https://json.nlohmann.me/api/basic_json_view/operator%5B%5D/index.md)/[`at`](https://json.nlohmann.me/api/basic_json_view/at/index.md)/[`find`](https://json.nlohmann.me/api/basic_json_view/find/index.md)/[`contains`](https://json.nlohmann.me/api/basic_json_view/contains/index.md), which resolve to the *first* occurrence (see the [Notes on duplicate keys](https://json.nlohmann.me/api/basic_json_view/operator%5B%5D/#notes)).

No pointers, references, or implicit conversion

Unlike `BasicJsonType`, `basic_json_view` has no stored value anywhere to hand out a pointer or a reference to, so it provides neither `get_ptr()`, `get_ref()`, nor `operator ValueType()`. [`get_string()`](https://json.nlohmann.me/api/basic_json_view/get_string/index.md) (equivalently, `get<string_view_t>()`) is the zero-copy alternative for strings.

## Examples

Example

The example below reads typed fields straight into C++ variables, collects a view of every array element with `get<std::vector<basic_json_view>>()` instead of a value, and converts a nested object into a user type through its `from_json()` -- which runs on a `BasicJsonType` value `materialize()` builds for just that one member.

```
#include <iostream>
#include <nlohmann/json_view.hpp>
#include <string>
#include <vector>

using json_document = nlohmann::json_document;
using json_view = nlohmann::json_view;

// address has no direct conversion in get<T>(), so get<address>() falls back
// to materialize().get<address>() -- a real nlohmann::json value is built
// for just this one member, and its own from_json() runs on that
struct address
{
    std::string city;
    int zip = 0;
};

void from_json(const nlohmann::json& j, address& a)
{
    j.at("city").get_to(a.city);
    j.at("zip").get_to(a.zip);
}

int main()
{
    json_document doc = json_document::parse(R"(
      {
        "name": "Alice",
        "active": true,
        "orders": [1, 2, 3],
        "address": {"city": "Berlin", "zip": 10115}
      }
    )");
    const json_view customer = doc.root();

    // read typed fields straight into C++ variables -- none of these build
    // a nlohmann::json value
    const std::string name = customer["name"].get<std::string>();
    const bool active = customer["active"].get<bool>();
    std::cout << name << (active ? " (active)" : " (inactive)") << '\n';

    // std::vector<json_view> keeps views of the array elements instead of
    // copies of their values
    bool first = true;
    for (const json_view order : customer["orders"].get<std::vector<json_view>>())
    {
        std::cout << (first ? "" : " ") << order.get<int>();
        first = false;
    }
    std::cout << '\n';

    // everything else goes through materialize()
    const address a = customer["address"].get<address>();
    std::cout << a.city << ' ' << a.zip << '\n';
}
```

Output:

```
Alice (active)
1 2 3
Berlin 10115
```

## See also

- [get_to](https://json.nlohmann.me/api/basic_json_view/get_to/index.md) - convert and write into a passed value
- [get_string](https://json.nlohmann.me/api/basic_json_view/get_string/index.md) - the string, without a copy
- [number_token](https://json.nlohmann.me/api/basic_json_view/number_token/index.md) - a number's token text, without a copy
- [materialize](https://json.nlohmann.me/api/basic_json_view/materialize/index.md) - build the `BasicJsonType` value of this subtree
- [`BasicJsonType::get`](https://json.nlohmann.me/api/basic_json/get/index.md) - the corresponding function of `basic_json`

## Version history

- Added in version 3.13.0 unreleased.
