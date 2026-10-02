# <small>nlohmann::basic_json_document::</small>insert

```cpp
template<typename I, typename V>
view_type insert(view_type array, I idx, V&& value);
```

Only an **editable** document (`#!cpp Editable == true`, e.g. [`json_editable_document`](../json_editable_document.md))
has `insert`; calling it on a read-only `basic_json_document` fails to compile (`#!cpp static_assert`).

Inserts `value` into `array` as a new element before position `idx`, which must not be past the end
(`#!cpp idx <= array.size()`; `#!cpp idx == array.size()` appends, like [`push_back`](push_back.md)). Unlike
[`push_back`](push_back.md), a [null](../basic_json_view/is_null.md) `array` does *not* first become an empty array:
`array` must already be an array.

`value` is accepted three ways: a [`basic_json_view`](../basic_json_view/index.md) of *any* document -- read-only or
editable, and it does not have to be `array`'s own document -- which is copied so that nothing is shared with the
source document afterward; a `BasicJsonType` value; or anything `BasicJsonType` can be constructed from (numbers,
strings, `#!cpp bool`, `#!cpp nullptr`, containers, ...).

## Template parameters

`I`
:   an integral type other than `#!cpp bool`, deduced (overloads taking a `#!cpp bool` or a non-integral type for
    `idx` do not participate in overload resolution).

`V`
:   the type of `value`, deduced; see above for what is accepted.

## Parameters

`array` (in)
:   the array to insert into

`idx` (in)
:   the position to insert `value` before; a negative value throws (see [Exceptions](#exceptions))

`value` (in)
:   the value to insert

## Return value

a view of the new element, now holding `value`

## Exception safety

Basic exception safety: `value` is fully encoded -- including the checks below -- into storage owned by the document
before anything already reachable from [`root()`](root.md) is touched, so a failure while encoding `value` (an
invalid argument, or `#!cpp std::bad_alloc`) leaves the document completely unchanged, other than memory allocated
for the encoding that is not reclaimed. A failure of a later allocation -- while `array` switches from its parsed
layout to a growable block, or while that block grows, see [Notes](#notes) -- can still leave `array` already
switched to that layout even though `value` itself was not inserted.

## Exceptions

Throws [`type_error.309`](../../home/exceptions.md#jsonexceptiontype_error309) if `array` is not an array -- the same
message [`BasicJsonType::insert`](../basic_json/insert.md) throws for the same type; a null `array` throws this too
(see above). Throws [`out_of_range.401`](../../home/exceptions.md#jsonexceptionout_of_range401) if `idx` is negative,
or if `#!cpp idx > array.size()`. Throws
[`invalid_iterator.202`](../../home/exceptions.md#jsonexceptioninvalid_iterator202) ("view does not belong to this
document") if `array` is a [discarded](../basic_json_view/is_discarded.md) view or a view of a *different* document.
Throws [`type_error.302`](../../home/exceptions.md#jsonexceptiontype_error302) if `value` is a
[discarded](../basic_json_view/is_discarded.md) view or a [discarded](../basic_json/is_discarded.md) `BasicJsonType`
value, and [`type_error.319`](../../home/exceptions.md#jsonexceptiontype_error319) if `value` is (or contains) a
binary value -- `BasicJsonType` can hold one, but a `json_document` cannot. Throws
[`type_error.316`](../../home/exceptions.md#jsonexceptiontype_error316) if `value` is (or contains) a string that is
not valid UTF-8, with the same message [`BasicJsonType::dump()`](../basic_json/dump.md) gives for that string.

## Complexity

Linear in the number of elements of `array` at or after `idx` (they move one slot over), plus time linear in the
size of `value` to encode it into the document's storage (constant for a scalar, linear in the number of nested
values for an array or object): like [`push_back`](push_back.md), the elements of `array` move to a growable block
of links the first time it is inserted into (or [`set`](set.md)/[`push_back`](push_back.md) on), and that block
grows in amortized constant time; inserting before the end within that block still shifts every later element.

## Notes

Like [`set`](set.md) on a member or an element, `insert` never moves an existing *element's value* -- only where
`array`'s *links* to its elements live -- so a view of an existing element of `array` stays valid across an
`insert`, and keeps referring to the same element even though its index shifts. Any iterator already taken over
`array` is invalidated, since it was walking the old layout. See [Edits](index.md#edits) for what stays valid across
an edit in general.

## Examples

??? example

    The example below inserts a step into the middle of a deployment plan, without touching the steps that come
    after it, and shows that a view taken before the insert keeps referring to the same element even though its
    index shifts -- something a plain `json`/`ordered_json` array, or its `std::vector`-based storage, has no
    equivalent for.

    ```cpp
    --8<-- "examples/basic_json_document__insert.cpp"
    ```

    Output:

    ```json
    --8<-- "examples/basic_json_document__insert.output"
    ```

## See also

- [push_back](push_back.md) - append to an array
- [erase](erase.md) - remove an object member, an array element, or the value a JSON pointer refers to
- [set](set.md) - replace a value, or set an object member, an array element, or the value a JSON pointer refers to
- [`BasicJsonType::insert`](../basic_json/insert.md) - the corresponding function of `basic_json`
- [Edits](index.md#edits) - what an edit guarantees, for every overload

## Version history

- Added in version 3.13.0.
