# Writing generic code

## View types

A view's type names its `BasicJsonType` and its [`view_mode`](../../api/view_mode.md):
[`json_view`](../../api/json_view.md) is `#!cpp basic_json_view<json, view_mode::read_only>`, and
[`json_editable_view`](../../api/json_editable_view.md) is `#!cpp basic_json_view<json, view_mode::editable>`. These
are different types. The only conversion between them turns a view of a read-only document into a view of an
editable document of the same `BasicJsonType`, so a function written for one shortcut accepts few other views:

```cpp
void print_names(json_view v);           // accepts neither an ordered_json_view nor a json_editable_view
void print_names(json_editable_view v);  // also accepts a json_view, but no ordered_json_view
```

This is the same pitfall as a `to_json`/`from_json` written for `json` instead of any `BasicJsonType`, which then does
not work for `ordered_json`. The shortcuts are for declaring documents and views; a function that takes a view names
the views it accepts with a template:

```cpp
// views of editable documents only
template<typename BasicJsonType>
void f(basic_json_view<BasicJsonType, view_mode::editable> v);

// views of read-only documents only
template<typename BasicJsonType>
void f(basic_json_view<BasicJsonType, view_mode::read_only> v);

// views of either document type
template<typename BasicJsonType, view_mode Mode>
void f(basic_json_view<BasicJsonType, Mode> v);
```

Views are passed by value: they are two pointers, cheap to copy, like a `#!cpp std::string_view`. A `const&` works as
well, but a non-`const` reference does not bind to the views that
[`root()`](../../api/basic_json_document/root.md), [`operator[]`](../../api/basic_json_view/operator%5B%5D.md), and
[`at()`](../../api/basic_json_view/at.md) return, so `#!cpp f(doc.root())` would not compile.

There is no conversion from an editable view to a read-only one, by design: the mode decides how a view walks the
index. A read-only view reads a container in place, while a view of an editable document follows the links that edits
leave behind, so a read-only view of an edited document would read stale values. The other direction is safe: a
read-only document has no edits, so a view of it [converts](../../api/basic_json_view/basic_json_view.md) to an
editable view, which reads it like an editable document before its first edit. A template deduces the mode without
conversions, so the template forms above still accept only the modes they name. Views of both modes compare with
[`operator==`](../../api/basic_json_view/operator_eq.md).

[`is_json_view<T>`](../../api/is_json_view.md) tells views from other types, for constraints that cannot be written as
a `basic_json_view<...>` parameter.

## A `from_json()` that reads views

[`get<T>()`](../../api/basic_json_view/get.md) on a view calls `T`'s `from_json()` with the view itself if that
`from_json()` accepts views, and with [`materialize()`](../../api/basic_json_view/materialize.md) otherwise. The
`from_json()` functions of the [`NLOHMANN_DEFINE_TYPE_*`](../../api/macros/nlohmann_define_type_intrusive.md),
[`NLOHMANN_DEFINE_DERIVED_TYPE_*`](../../api/macros/nlohmann_define_derived_type.md), and
[`NLOHMANN_JSON_SERIALIZE_ENUM`](../../api/macros/nlohmann_json_serialize_enum.md) macros, and those of the library
for the standard types, accept views, so these types need nothing else. For decoding the statuses of
twitter.json into structs, reading the view is about 5 times faster than `#!cpp materialize().get<T>()`.

A hand-written `from_json()` reads views if it is constrained to `json` values and views:

```cpp
template < typename J, typename std::enable_if <
               nlohmann::is_json_view<J>::value || std::is_same<J, nlohmann::json>::value, int >::type = 0 >
void from_json(const J& j, person& p)
{
    p.name = j.at("name").template get<std::string>();
    p.age = j.at("age").template get<int>();
}
```

Its body may only use what views and `basic_json` have in common: the type checks, `at()`, `operator[]`,
`contains()`, `value()`, `size()`, iteration and `items()`, and `get<T>()`/`get_to()`. An unconstrained
`#!cpp template<typename BasicJsonType> void from_json(const BasicJsonType& j, person& p)`, as in
[arbitrary type conversions](../arbitrary_types.md), is never called with a view, as it might use `basic_json`
functions a view does not have; such a type is converted through `materialize()`. A `from_json()` for `json` only is
converted through `materialize()` as well.

Reading the view and `#!cpp materialize().get<T>()` give the same result, except for an object with a repeated key;
see [Duplicate keys](differences.md#duplicate-keys).

`to_json()` is unaffected: it writes `basic_json` values, never views.

## See also

- [Zero-copy JSON views](index.md) - overview
- [`is_json_view`](../../api/is_json_view.md) - type trait to detect views
- [`view_mode`](../../api/view_mode.md) - read-only and editable views
- [Reading values](reading.md) - what `get<T>()` converts without materializing

## Version history

- Added in version 3.13.0.
