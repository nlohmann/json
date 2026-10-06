# <small>nlohmann::basic_json_view::</small>operator==

```cpp
// (1)
bool operator==(const basic_json_view& lhs, const basic_json_view& rhs);

// (2)
bool operator==(const basic_json_view& lhs, const BasicJsonType& rhs);
bool operator==(const BasicJsonType& lhs, const basic_json_view& rhs);
```

1. Compares two views for equality: whether the values [`BasicJsonType::parse()`](../basic_json/parse.md) would
   produce for `lhs` and `rhs` are equal, according to `BasicJsonType`'s [`operator==`](../basic_json/operator_eq.md).
2. Compares a view and a `BasicJsonType` value for equality, in either order: whether the value `parse()` would
   produce for the view and the other operand are equal, according to `BasicJsonType`'s
   [`operator==`](../basic_json/operator_eq.md).

Neither overload builds a `BasicJsonType` value for a view to do the comparison (see [Notes](#notes) below). Numbers
compare by value across their types (`#!cpp 1 == 1.0`), and an object compares by its members, with duplicate keys
resolved exactly as `parse()` resolves them -- the last value, at the position of the first occurrence of the key.

## Parameters

`lhs` (in)
:   first value to consider

`rhs` (in)
:   second value to consider

## Return value

whether the values `lhs` and `rhs` are equal

## Exception safety

Strong exception safety: if an exception is thrown, there are no changes to either operand, or to the document(s) a
view refers to.

## Exceptions

May throw `#!cpp std::bad_alloc`. Unlike the other comparison and most other `basic_json_view` functions,
`operator==` is not `#!cpp noexcept`: resolving an object's members needs a temporary array to sort them by key (see
[Complexity](#complexity) below), and that allocation can fail.

## Complexity

Linear in the size of the compared values: every number, string, array element, and object member is visited at most
once, and the walk is iterative, so the nesting depth it can compare is limited by available memory only, not by the
call stack (as for [`materialize()`](materialize.md)). Resolving an object's members takes an additional O(n log n)
in the number of members at that level, since they are sorted by key to detect and resolve duplicates before being
compared. Two arrays of different [`size()`](size.md) are rejected without visiting either one's elements.

## Notes

Only a single number, boolean, or `#!cpp null` value is ever materialized into a `BasicJsonType`, to reuse its
`operator==` -- for numbers, so that values written differently in the source text but equal in value (e.g. an
integer and a floating-point literal) still compare equal, following the same rules `BasicJsonType` does for special
values such as `#!cpp NaN`. Constructing one of these scalars never allocates. Strings are compared directly, without
allocating, either from the source text on both sides or, for overload 2, against `BasicJsonType`'s own string.
Arrays and objects are never materialized at all; only their elements or members are visited, one pair at a time.

!!! info "How objects are compared"

    For a [`json_view`](../json_view.md) (`BasicJsonType::object_t` is `#!cpp std::map`), members are compared by
    key, regardless of the order they appear in the source text. For an
    [`ordered_json_view`](../ordered_json_view.md) (`object_t` is `ordered_map`), they are compared in the order
    they occur, so the very same two objects with their members reordered can compare equal as `json_view`s but not
    as `ordered_json_view`s. This is exactly how [`json`](../json.md) and [`ordered_json`](../ordered_json.md)
    compare, see ["Comparing different `basic_json` specializations"](../basic_json/operator_eq.md#notes).

!!! info "Discarded views"

    A [discarded](is_discarded.md) view compares the same way a discarded `BasicJsonType` value does, which is
    governed by
    [`JSON_USE_LEGACY_DISCARDED_VALUE_COMPARISON`](../macros/json_use_legacy_discarded_value_comparison.md): by
    default, a discarded view is never equal to anything, not even another discarded view.

No ordering comparison (`#!cpp operator<`) is provided for `basic_json_view`; [`materialize()`](materialize.md) is
the way to get a `BasicJsonType` value that supports it.

## Examples

??? example

    The example below checks whether a newly received configuration differs from the previous one, and whether a
    received document matches what a test expects -- directly on views, without ever materializing a `BasicJsonType`
    value for either side.

    ```cpp
    --8<-- "examples/basic_json_view__operator_eq.cpp"
    ```

    Output:

    ```json
    --8<-- "examples/basic_json_view__operator_eq.output"
    ```

## See also

- [operator!=](operator_ne.md) - compare for inequality
- [materialize](materialize.md) - build a `BasicJsonType` value, e.g. to keep comparing after the document is gone
- [`BasicJsonType::operator==`](../basic_json/operator_eq.md) - the corresponding function of `basic_json`

## Version history

- Added in version 3.13.0.
