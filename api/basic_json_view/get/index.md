# nlohmann::basic_json_view::get

```
template<typename T>
T get() const;
```

Converts the value to `T`.

For the types below, the conversion works directly on the flat index — no `BasicJsonType` value is built for it:

- `bool`
- arithmetic types other than `bool` (for a boolean, `0`/`1`, exactly as for [`BasicJsonType::get<T>()`](https://json.nlohmann.me/api/basic_json/get/index.md))
- `std::nullptr_t`
- `std::basic_string<char, Traits, Alloc>` (including `string_t`) — a copy of the string
- [`string_view_t`](https://json.nlohmann.me/api/basic_json_view/#member-types) — **no copy**: the returned view points into the document's [`source()`](https://json.nlohmann.me/api/basic_json_document/source/index.md) text, or, for a string that contains escape sequences, into the document's own buffer of decoded strings (see [`get_string()`](https://json.nlohmann.me/api/basic_json_view/get_string/index.md))
- `BasicJsonType` — equivalent to [`materialize()`](https://json.nlohmann.me/api/basic_json_view/materialize/index.md)
- `basic_json_view` — returns `*this`
- `std::vector<U, A>` of the types above — from an array, element by element, each converted with `get<U>()`; `std::vector<basic_json_view>` keeps a view of every element instead of a value
- `std::map<K, basic_json_view, C, A>` and `std::unordered_map<K, basic_json_view, H, E, A>`, if `K` is constructible from a `(const char*, std::size_t)` pair — views of the members of an object; with a repeated key, the view of the *last* member is kept, as [`BasicJsonType::parse()`](https://json.nlohmann.me/api/basic_json/parse/index.md) keeps its value

A default-constructible `T` whose `from_json()` accepts views reads the view directly as well, without building a `BasicJsonType` value. This covers the library's own conversions of the standard library types — all other `std::vector`s, `std::map`/`std::unordered_map` (also with other key types), `std::list`, `std::deque`, `std::set`, `std::forward_list`, `std::valarray`, `std::array`, C arrays, `std::pair`, `std::tuple`, `std::optional`, enumerations, `std::filesystem::path`, ... -- which give the same values as `materialize().get<T>()` (from an object, a repeated key keeps the *last* value, as [`BasicJsonType::parse()`](https://json.nlohmann.me/api/basic_json/parse/index.md) does), as well as the types of the [`NLOHMANN_DEFINE_TYPE_*`](https://json.nlohmann.me/api/macros/nlohmann_define_type_intrusive/index.md) and [`NLOHMANN_DEFINE_DERIVED_TYPE_*`](https://json.nlohmann.me/api/macros/nlohmann_define_derived_type/index.md) macros and the enumerations of [`NLOHMANN_JSON_SERIALIZE_ENUM`](https://json.nlohmann.me/api/macros/nlohmann_json_serialize_enum/index.md), and any `from_json()` constrained to accept views, e.g. with [`is_json_view`](https://json.nlohmann.me/api/is_json_view/index.md). A `from_json()` that also accepts types that are no JSON values at all, such as the unconstrained `template<typename BasicJsonType> void from_json(const BasicJsonType&,T&)` of [arbitrary type conversions](https://json.nlohmann.me/features/arbitrary_types/index.md), is not called with a view: it may use `BasicJsonType` functions a view does not have. See [Writing generic code](https://json.nlohmann.me/features/json_view/#writing-generic-code).

Duplicate keys

Such a `from_json()` looks members up in the view, where a repeated key finds the **first** member, while `materialize().get<T>()` sees the **last** one, as [`BasicJsonType::parse()`](https://json.nlohmann.me/api/basic_json/parse/index.md) keeps it: for `{"x":1,"x":2}`, `get<point>()` reads `x == 1`. See [Duplicate keys](https://json.nlohmann.me/features/json_view/#duplicate-keys).

Every other `T` — user types whose `from_json()` is written for `BasicJsonType` only, types without a default constructor, `std::tuple`s holding references, ... — is converted by `materialize().get<T>()`: the subtree is built into a real `BasicJsonType` value first (as [`BasicJsonType::parse()`](https://json.nlohmann.me/api/basic_json/parse/index.md) would), and converted from there exactly as [`BasicJsonType::get<T>()`](https://json.nlohmann.me/api/basic_json/get/index.md) would convert it.

## Template parameters

`T` : the type to convert the value to

## Return value

the value, converted to `T`

## Exception safety

Strong guarantee: there are no changes to the view or the document it refers to.

## Exceptions

- For the directly-converted types listed above (other than `BasicJsonType` and `basic_json_view`, which never throw): throws [`type_error.302`](https://json.nlohmann.me/home/exceptions/#jsonexceptiontype_error302) if the value's type does not match `T` — the same exception, with the same message, that [`BasicJsonType::get<T>()`](https://json.nlohmann.me/api/basic_json/get/index.md) throws for the same JSON type and `T`.
- For `std::vector<U, A>`: throws `type_error.302` if the value is not an array; otherwise, whatever converting an element to `U` throws.
- For `std::map`/`std::unordered_map` of views: throws `type_error.302` if the value is not an object.
- For a `T` whose `from_json()` reads the view: whatever that `from_json()` throws; for the library's conversions and the macros, the same exceptions with the same messages as [`BasicJsonType::get<T>()`](https://json.nlohmann.me/api/basic_json/get/index.md) of the same value.
- For every other `T`: whatever [`materialize().get<T>()`](https://json.nlohmann.me/api/basic_json/get/index.md) throws — typically `type_error.302`, or whatever a user-provided `from_json()` throws.

None of the exceptions thrown directly by this function or by a `from_json()` that reads the view (the first four bullets above) carry a [`JSON_DIAGNOSTICS`](https://json.nlohmann.me/api/macros/json_diagnostics/index.md) path: the view has no `BasicJsonType` value to point at. An exception thrown while converting through `materialize()` (the last bullet) is different: it is thrown by a real `BasicJsonType` value, so it **does** carry a `JSON_DIAGNOSTICS` path if `BasicJsonType` was built with it enabled. That path is relative to the root of the view's subtree, because `materialize()` builds only the subtree (with parent pointers): it is empty if the failing value is the subtree's root itself, and it never is the path within the whole document.

## Complexity

- `bool`, arithmetic types, `std::nullptr_t`, [`string_view_t`](https://json.nlohmann.me/api/basic_json_view/#member-types), `basic_json_view`: constant.
- `std::basic_string<char, Traits, Alloc>`: constant, plus one allocation and a copy of the string's bytes.
- `BasicJsonType`: linear in the size of the subtree, see [`materialize()`](https://json.nlohmann.me/api/basic_json_view/materialize/index.md).
- `std::vector<U, A>`: linear in the number of elements, times the complexity of converting one element to `U`.
- `std::map`/`std::unordered_map`: linear in the number of members for walking them, plus the container's own insertion cost per member (logarithmic for `std::map`, amortized constant for `std::unordered_map`), times the complexity of converting one member to the mapped type.
- a `T` whose `from_json()` reads the view: the cost of that `from_json()`; for the macros, linear in the number of members times the cost of a lookup, plus the cost of converting the members.
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

The example below reads typed fields straight into C++ variables, collects a view of every array element with `get<std::vector<basic_json_view>>()` instead of a value, and converts a nested object into a user type through its `from_json()` — which runs on a `BasicJsonType` value `materialize()` builds for just that one member.

```
#include <iostream>
#include <nlohmann/json_view.hpp>
#include <string>
#include <vector>

using nlohmann::json_document;
using nlohmann::json_view;

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

- [`get_to`](https://json.nlohmann.me/api/basic_json_view/get_to/index.md) - convert and write into a passed value
- [`get_string`](https://json.nlohmann.me/api/basic_json_view/get_string/index.md) - the string, without a copy
- [`number_token`](https://json.nlohmann.me/api/basic_json_view/number_token/index.md) - a number's token text, without a copy
- [`materialize`](https://json.nlohmann.me/api/basic_json_view/materialize/index.md) - build the `BasicJsonType` value of this subtree
- [`BasicJsonType::get`](https://json.nlohmann.me/api/basic_json/get/index.md) - the corresponding function of `basic_json`
- [Zero-copy JSON views](https://json.nlohmann.me/features/json_view/#getting-values-out-without-copying) - which conversions avoid building a basic_json value

## Version history

- Added in version 3.13.0 unreleased.
