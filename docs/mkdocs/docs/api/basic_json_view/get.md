# <small>nlohmann::basic_json_view::</small>get

```cpp
template<typename T>
T get() const;
```

Converts the value to `T`.

For the types below, the conversion works directly on the flat index -- no `BasicJsonType` value is built for it:

- `#!cpp bool`
- arithmetic types other than `#!cpp bool` (from a number; from a boolean, as `#!cpp 0`/`#!cpp 1`, exactly as
  [`BasicJsonType::get<T>()`](../basic_json/get.md) converts a boolean)
- `#!cpp std::nullptr_t`
- `#!cpp std::basic_string<char, Traits, Alloc>` (including `string_t`) -- a copy of the string
- [`string_view_t`](index.md#member-types) -- **no copy**: the returned view points into the document's
  [`source()`](../basic_json_document/source.md) text, or, for a string that contains escape sequences, into the
  document's own buffer of decoded strings (see [`get_string()`](get_string.md))
- `BasicJsonType` -- equivalent to [`materialize()`](materialize.md)
- `basic_json_view` -- returns `#!cpp *this`
- `#!cpp std::vector<U, A>` -- element by element, each converted with `#!cpp get<U>()`; `#!cpp
  std::vector<basic_json_view>` keeps a view of every element instead of a value
- `#!cpp std::map<K, V, C, A>` and `#!cpp std::unordered_map<K, V, H, E, A>`, if `K` is constructible from a `#!cpp
  (const char*, std::size_t)` pair -- member by member, each value converted with `#!cpp get<V>()`; with a repeated
  key, the *last* value is kept, as [`BasicJsonType::parse()`](../basic_json/parse.md) (and
  [`materialize()`](materialize.md)) does; `#!cpp std::map<std::string, basic_json_view>` keeps views of the members
  instead of values

Every other `T` -- `#!cpp std::list`, `#!cpp std::pair`, `#!cpp std::array`, enumerations, user types with a
`from_json()`, ... -- is converted by `#!cpp materialize().get<T>()`: the subtree is built into a real `BasicJsonType`
value first (as [`BasicJsonType::parse()`](../basic_json/parse.md) would), and converted from there exactly as
[`BasicJsonType::get<T>()`](../basic_json/get.md) would convert it.

## Template parameters

`T`
:   the type to convert the value to

## Return value

the value, converted to `T`

## Exception safety

Strong exception safety: if an exception is thrown, there are no changes to the view or the document it refers to.

## Exceptions

- For the directly-converted types listed above (other than `BasicJsonType` and `basic_json_view`, which never
  throw): throws [`type_error.302`](../../home/exceptions.md#jsonexceptiontype_error302) if the value's type does not
  match `T` -- the same exception, with the same message, that [`BasicJsonType::get<T>()`](../basic_json/get.md)
  throws for the same JSON type and `T`.
- For `#!cpp std::vector<U, A>`: throws `type_error.302` if the value is not an array; otherwise, whatever converting
  an element to `U` throws.
- For `#!cpp std::map`/`#!cpp std::unordered_map`: throws `type_error.302` if the value is not an object; otherwise,
  whatever converting a member to the mapped type throws.
- For every other `T`: whatever [`materialize().get<T>()`](../basic_json/get.md) throws -- typically `type_error.302`,
  or whatever a user-provided `from_json()` throws.

None of the exceptions thrown directly by this function (the first three bullets above) carry a
[`JSON_DIAGNOSTICS`](../macros/json_diagnostics.md) path: the view has no `BasicJsonType` value to point at. An
exception thrown while converting through `materialize()` (the last bullet) is different: it is thrown by a real
`BasicJsonType` value, so it **does** carry a `JSON_DIAGNOSTICS` path if `BasicJsonType` was built with it enabled.

## Complexity

- `#!cpp bool`, arithmetic types, `#!cpp std::nullptr_t`, [`string_view_t`](index.md#member-types), `basic_json_view`:
  constant.
- `#!cpp std::basic_string<char, Traits, Alloc>`: constant, plus one allocation and a copy of the string's bytes.
- `BasicJsonType`: linear in the size of the subtree, see [`materialize()`](materialize.md).
- `#!cpp std::vector<U, A>`: linear in the number of elements, times the complexity of converting one element to `U`.
- `#!cpp std::map`/`#!cpp std::unordered_map`: linear in the number of members for walking them, plus the container's
  own insertion cost per member (logarithmic for `#!cpp std::map`, amortized constant for `#!cpp
  std::unordered_map`), times the complexity of converting one member to the mapped type.
- every other `T`: linear in the size of the subtree (building the `BasicJsonType` value), plus the complexity of
  [`BasicJsonType::get<T>()`](../basic_json/get.md) on it.

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
    --8<-- "examples/basic_json_view__get.cpp"
    ```

    Output:

    ```json
    --8<-- "examples/basic_json_view__get.output"
    ```

## See also

- [get_to](get_to.md) - convert and write into a passed value
- [get_string](get_string.md) - the string, without a copy
- [number_token](number_token.md) - a number's token text, without a copy
- [materialize](materialize.md) - build the `BasicJsonType` value of this subtree
- [`BasicJsonType::get`](../basic_json/get.md) - the corresponding function of `basic_json`

## Version history

- Added in version 3.13.0.
