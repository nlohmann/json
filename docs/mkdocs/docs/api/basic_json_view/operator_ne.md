# <small>nlohmann::basic_json_view::</small>operator!=

```cpp
// (1)
bool operator!=(const basic_json_view& lhs, const basic_json_view& rhs);

// (2)
bool operator!=(const basic_json_view& lhs, const BasicJsonType& rhs);
bool operator!=(const BasicJsonType& lhs, const basic_json_view& rhs);
```

1. Compares two views for inequality. Returns `#!cpp !(lhs == rhs)`, see [operator==](operator_eq.md).
2. Compares a view and a `BasicJsonType` value for inequality, in either order. Returns `#!cpp !(lhs == rhs)` (or,
   for the reversed order, `#!cpp !(rhs == lhs)`), see [operator==](operator_eq.md).

Since `operator!=` is defined as the negation of [`operator==`](operator_eq.md), it follows the same rules for
special cases: for instance, since a [discarded](is_discarded.md) view is never equal to anything by default (see
[operator=='s Notes](operator_eq.md#notes)), it is never *unequal* to anything either -- `#!cpp discarded != discarded`
is also `#!cpp false`, exactly as for a discarded `BasicJsonType` value.

## Parameters

`lhs` (in)
:   first value to consider

`rhs` (in)
:   second value to consider

## Return value

whether the values `lhs` and `rhs` are not equal

## Exception safety

Strong exception safety: if an exception is thrown, there are no changes to either operand, or to the document(s) a
view refers to.

## Exceptions

May throw `#!cpp std::bad_alloc`, propagated from [`operator==`](operator_eq.md#exceptions). Unlike most other
`basic_json_view` functions, `operator!=` is not `#!cpp noexcept`.

## Complexity

Linear, as [`operator==`](operator_eq.md#complexity).

## Notes

See the [Notes](operator_eq.md#notes) of `operator==` -- in particular for how an object's members are compared
(order matters for [`ordered_json_view`](../ordered_json_view.md) but not for [`json_view`](../json_view.md)) and
for how discarded views compare.

No ordering comparison (`#!cpp operator<`) is provided for `basic_json_view`; [`materialize()`](materialize.md) is
the way to get a `BasicJsonType` value that supports it.

## Examples

??? example

    The example below asserts, as a test would, that a received document differs from an unwanted value, and shows
    that -- as for [`json`](../json.md)/[`ordered_json`](../ordered_json.md) -- reordering an object's members is
    detected as a difference for an `ordered_json_view` but not for a `json_view`.

    ```cpp
    --8<-- "examples/basic_json_view__operator_ne.cpp"
    ```

    Output:

    ```json
    --8<-- "examples/basic_json_view__operator_ne.output"
    ```

## See also

- [operator==](operator_eq.md) - compare for equality
- [materialize](materialize.md) - build a `BasicJsonType` value, e.g. to keep comparing after the document is gone
- [`BasicJsonType::operator!=`](../basic_json/operator_ne.md) - the corresponding function of `basic_json`

## Version history

- Added in version 3.13.0.
