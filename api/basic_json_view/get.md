# <small>nlohmann::basic_json_view::</small>get

```cpp
template<typename T>
T get() const;
```

Converts the value to `T`.

For the types below, the conversion works directly on the flat index -- no `BasicJsonType` value is built for it:

- `#!cpp bool`
- arithmetic types other than `#!cpp bool` (for a boolean, `#!cpp 0`/`#!cpp 1`, exactly as for
  [`BasicJsonType::get<T>()`](../basic_json/get.md))
- `#!cpp std::nullptr_t`
- `#!cpp std::basic_string<char, Traits, Alloc>` (including `string_t`) -- a copy of the string
- [`string_view_t`](index.md#member-types) -- **no copy**: the returned view points into the document's
  [`source()`](../basic_json_document/source.md) text, or, for a string that contains escape sequences, into the
  document's own buffer of decoded strings (see [`get_string()`](get_string.md))
- `BasicJsonType` -- equivalent to [`materialize()`](materialize.md)
- `basic_json_view` -- returns `#!cpp *this`
- `#!cpp std::vector<U, A>` of the types above -- from an array, element by element, each converted with
  `#!cpp get<U>()`; `#!cpp std::vector<basic_json_view>` keeps a view of every element instead of a value
- `#!cpp std::map<K, basic_json_view, C, A>` and `#!cpp std::unordered_map<K, basic_json_view, H, E, A>`, if `K` is
  constructible from a `#!cpp (const char*, std::size_t)` pair -- views of the members of an object; with a repeated
  key, the view of the *last* member is kept, as [`BasicJsonType::parse()`](../basic_json/parse.md) keeps its value

A default-constructible `T` whose `from_json()` accepts views reads the view directly as well, without building a
`BasicJsonType` value. This covers the library's own conversions of the standard library types -- all other
`#!cpp std::vector`s, `#!cpp std::map`/`#!cpp std::unordered_map` (also with other key types), `#!cpp std::list`,
`#!cpp std::deque`, `#!cpp std::set`, `#!cpp std::forward_list`, `#!cpp std::valarray`, `#!cpp std::array`, C arrays,
`#!cpp std::pair`, `#!cpp std::tuple`, `#!cpp std::optional`, enumerations, `#!cpp std::filesystem::path`, ... --
which give the same values as `#!cpp materialize().get<T>()` (from an object, a repeated key keeps the *last* value,
as [`BasicJsonType::parse()`](../basic_json/parse.md) does), as well as the types of the
[`NLOHMANN_DEFINE_TYPE_*`](../macros/nlohmann_define_type_intrusive.md) and
[`NLOHMANN_DEFINE_DERIVED_TYPE_*`](../macros/nlohmann_define_derived_type.md) macros and the enumerations of
[`NLOHMANN_JSON_SERIALIZE_ENUM`](../macros/nlohmann_json_serialize_enum.md), and any `from_json()` constrained to
accept views, e.g. with [`is_json_view`](../is_json_view.md). A `from_json()` that also accepts types that are no JSON
values at all, such as the unconstrained `#!cpp template<typename BasicJsonType> void from_json(const BasicJsonType&,
T&)` of [arbitrary type conversions](../../features/arbitrary_types.md), is not called with a view: it may use
`BasicJsonType` functions a view does not have. See [Writing generic code](../../features/json_view.md#writing-generic-code).

!!! warning "Duplicate keys"

    Such a `from_json()` looks members up in the view, where a repeated key finds the **first** member, while
    `#!cpp materialize().get<T>()` sees the **last** one, as [`BasicJsonType::parse()`](../basic_json/parse.md)
    keeps it: for `#!cpp {"x":1,"x":2}`, `#!cpp get<point>()` reads `#!cpp x == 1`. See
    [Duplicate keys](../../features/json_view.md#duplicate-keys).

Every other `T` -- user types whose `from_json()` is written for `BasicJsonType` only, types without a default
constructor, `#!cpp std::tuple`s holding references, ... -- is converted by `#!cpp materialize().get<T>()`: the subtree is built into a real `BasicJsonType`
value first (as [`BasicJsonType::parse()`](../basic_json/parse.md) would), and converted from there exactly as
[`BasicJsonType::get<T>()`](../basic_json/get.md) would convert it.

## Template parameters

`T`
:   the type to convert the value to

## Return value

the value, converted to `T`

## Exception safety

Strong guarantee: there are no changes to the view or the document it refers to.

## Exceptions

- For the directly-converted types listed above (other than `BasicJsonType` and `basic_json_view`, which never
  throw): throws [`type_error.302`](../../home/exceptions.md#jsonexceptiontype_error302) if the value's type does not
  match `T` -- the same exception, with the same message, that [`BasicJsonType::get<T>()`](../basic_json/get.md)
  throws for the same JSON type and `T`.
- For `#!cpp std::vector<U, A>`: throws `type_error.302` if the value is not an array; otherwise, whatever converting
  an element to `U` throws.
- For `#!cpp std::map`/`#!cpp std::unordered_map` of views: throws `type_error.302` if the value is not an object.
- For a `T` whose `from_json()` reads the view: whatever that `from_json()` throws; for the library's conversions and
  the macros, the same exceptions with the same messages as [`BasicJsonType::get<T>()`](../basic_json/get.md) of the
  same value.
- For every other `T`: whatever [`materialize().get<T>()`](../basic_json/get.md) throws -- typically `type_error.302`,
  or whatever a user-provided `from_json()` throws.

None of the exceptions thrown directly by this function or by a `from_json()` that reads the view (the first four
bullets above) carry a
[`JSON_DIAGNOSTICS`](../macros/json_diagnostics.md) path: the view has no `BasicJsonType` value to point at. An
exception thrown while converting through `materialize()` (the last bullet) is different: it is thrown by a real
`BasicJsonType` value, so it **does** carry a `JSON_DIAGNOSTICS` path if `BasicJsonType` was built with it enabled.
That path is relative to the root of the view's subtree, because `materialize()` builds only the subtree (with parent
pointers): it is empty if the failing value is the subtree's root itself, and it never is the path within the whole
document.

## Complexity

- `#!cpp bool`, arithmetic types, `#!cpp std::nullptr_t`, [`string_view_t`](index.md#member-types), `basic_json_view`:
  constant.
- `#!cpp std::basic_string<char, Traits, Alloc>`: constant, plus one allocation and a copy of the string's bytes.
- `BasicJsonType`: linear in the size of the subtree, see [`materialize()`](materialize.md).
- `#!cpp std::vector<U, A>`: linear in the number of elements, times the complexity of converting one element to `U`.
- `#!cpp std::map`/`#!cpp std::unordered_map`: linear in the number of members for walking them, plus the container's
  own insertion cost per member (logarithmic for `#!cpp std::map`, amortized constant for `#!cpp
  std::unordered_map`), times the complexity of converting one member to the mapped type.
- a `T` whose `from_json()` reads the view: the cost of that `from_json()`; for the macros, linear in the number of
  members times the cost of a lookup, plus the cost of converting the members.
- every other `T`: the cost of [`materialize()`](materialize.md) and of destroying the `BasicJsonType` value
  afterwards, plus that of [`BasicJsonType::get<T>()`](../basic_json/get.md).

## Notes

!!! info "Floating-point values"

    A floating-point `T` is converted from the same digits the lexer would see during `#!cpp BasicJsonType::parse()`,
    using the same conversion, so the result is bit-for-bit identical to `#!cpp BasicJsonType::parse(text).get<T>()`
    for the same source text.

!!! info "Duplicate keys"

    `#!cpp std::map`/`#!cpp std::unordered_map` conversions keep the *last* value of a repeated key, like
    [`materialize()`](materialize.md) and [`BasicJsonType::parse()`](../basic_json/parse.md) do. This is the opposite
    of [`operator[]`](operator[].md)/[`at`](at.md)/[`find`](find.md)/[`contains`](contains.md), which resolve to the
    *first* occurrence (see the [Notes on duplicate keys](operator[].md#notes)).

!!! info "No pointers, references, or implicit conversion"

    Unlike `BasicJsonType`, `basic_json_view` has no stored value anywhere to hand out a pointer or a reference to, so
    it provides neither `#!cpp get_ptr()`, `#!cpp get_ref()`, nor `#!cpp operator ValueType()`.
    [`get_string()`](get_string.md) (equivalently, `#!cpp get<string_view_t>()`) is the zero-copy alternative for
    strings.

## Examples

??? example

    The example below reads typed fields straight into C++ variables, collects a view of every array element with
    `#!cpp get<std::vector<basic_json_view>>()` instead of a value, and converts a nested object into a user type
    through its `from_json()` -- which runs on a `BasicJsonType` value `materialize()` builds for just that one
    member.

    ```cpp
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

    ```json
    Alice (active)
    1 2 3
    Berlin 10115
    
    ```

## See also

- [get_to](get_to.md) - convert and write into a passed value
- [get_string](get_string.md) - the string, without a copy
- [number_token](number_token.md) - a number's token text, without a copy
- [materialize](materialize.md) - build the `BasicJsonType` value of this subtree
- [`BasicJsonType::get`](../basic_json/get.md) - the corresponding function of `basic_json`

## Version history

- Added in version 3.13.0.
