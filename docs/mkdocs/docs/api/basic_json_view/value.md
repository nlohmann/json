# <small>nlohmann::basic_json_view::</small>value

```cpp
// (1)
template<typename T>
T value(string_view_t key, const T& default_value) const;
string_t value(string_view_t key, const char* default_value) const;

// (2)
template<typename T>
T value(const json_pointer& ptr, const T& default_value) const;
string_t value(const json_pointer& ptr, const char* default_value) const;
```

1. Returns the value of the object member with key `key` -- the first one, should the key occur more than once (see
   [Notes on duplicate keys](operator[].md#notes)) -- converted to `T`, or `default_value` if there is no such member.
2. Returns the value a JSON pointer `ptr` refers to, starting at this value, converted to `T`, or `default_value` if
   `ptr` cannot be resolved.

Both overloads have a dedicated `#!cpp const char*` overload, so `#!cpp v.value(key, "default")` (and the JSON pointer
equivalent) deduce `string_t`, not `const char*`, for their return type and for the comparison used to pick between
`key` and `default_value`.

## Template parameters

`T`
:   the type to convert the found value to; also the type of `default_value`

## Parameters

`key` (in)
:   object key of the element to access

`ptr` (in)
:   JSON pointer to the element to access

`default_value` (in)
:   the value to return if `key`/`ptr` resolves to no value

## Return value

1. the first member with key `key`, converted to `T`, or `default_value`
2. the value `ptr` resolves to, converted to `T`, or `default_value`

## Exception safety

Strong exception safety: if an exception is thrown, there are no changes to the view or the document it refers to.

## Exceptions

1. Throws [`type_error.306`](../../home/exceptions.md#jsonexceptiontype_error306) if the value is not an object --
   the same exception, with the same message, that [`BasicJsonType::value`](../basic_json/value.md) throws for the
   same call. If a member with key `key` is found, throws whatever converting it to `T` throws (typically
   [`type_error.302`](../../home/exceptions.md#jsonexceptiontype_error302), with the same message
   [`BasicJsonType::value`](../basic_json/value.md) throws for the same mismatch); a missing member never throws.
2. Throws [`type_error.306`](../../home/exceptions.md#jsonexceptiontype_error306) if this value -- not the value `ptr`
   resolves to -- is neither an object nor an array. Throws [`parse_error.106`](../../home/exceptions.md#jsonexceptionparse_error106)
   or [`parse_error.109`](../../home/exceptions.md#jsonexceptionparse_error109) if `ptr` contains a malformed array
   index. If `ptr` resolves to a value, throws whatever converting it to `T` throws. Every other way `ptr` can fail to
   resolve -- a missing key, an out-of-range or "`-`" array index, an unresolvable token on a primitive -- yields
   `default_value` instead of throwing, exactly as [`BasicJsonType::value`](../basic_json/value.md) catches
   `out_of_range` and returns `default_value`.

None of these exceptions carry a [`JSON_DIAGNOSTICS`](../macros/json_diagnostics.md) path: the view has no
`BasicJsonType` value to point at, so the exception is created without one, even if `BasicJsonType` was built with
`JSON_DIAGNOSTICS` enabled.

## Complexity

1. Linear in the number of members: as for [`operator[]`](operator[].md#complexity), members are compared one after
   another, in document order, stopping at the first match. Plus the complexity of converting the found member to
   `T` (see [`get`](get.md)).
2. Linear in the number of reference tokens of `ptr` and, for each token, in the number of members of the object at
   that level or the index into the array -- as for the [`operator[]`](operator[].md#complexity) and
   [`at`](at.md#complexity) overloads that take a JSON pointer. Plus the complexity of converting the resolved value
   to `T`.

## Notes

!!! info "Differences to `at` and `operator[]`"

    Unlike [`at`](at.md), this function does not throw if `key`/`ptr` resolves to no value. Unlike
    [`operator[]`](operator[].md), it never returns a [discarded](is_discarded.md) view -- it always returns a `T` --
    and it is available on any view, since it never needs to insert a missing element the way the non-const
    `BasicJsonType::operator[]` would.

!!! info "Which values can be asked"

    As for [`BasicJsonType::value`](../basic_json/value.md), the key overload (1) requires an object, and the JSON
    pointer overload (2) an object or an array.

## Examples

??? example "Example: (1) access specified object element with default value"

    The example below reads a couple of optional configuration fields with a default, so that a missing key never
    needs a `#!cpp try`/`#!cpp catch` of its own.

    ```cpp
    --8<-- "examples/basic_json_view__value.cpp"
    ```

    Output:

    ```json
    --8<-- "examples/basic_json_view__value.output"
    ```

??? example "Example: (2) access specified element via JSON pointer with default value"

    The example below reads an optional, nested configuration value with a default, given as a JSON pointer.

    ```cpp
    --8<-- "examples/basic_json_view__value_json_pointer.cpp"
    ```

    Output:

    ```json
    --8<-- "examples/basic_json_view__value_json_pointer.output"
    ```

## See also

- [at](at.md) - access specified element with bounds checking (throws instead of returning a default value)
- [operator[]](operator[].md) - access specified element (returns a discarded view instead of a default value)
- [`BasicJsonType::value`](../basic_json/value.md) - the corresponding function of `basic_json`

## Version history

- Added in version 3.13.0.
