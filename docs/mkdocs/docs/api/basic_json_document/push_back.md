# <small>nlohmann::basic_json_document::</small>push_back

```cpp
template<typename V>
view_type push_back(view_type array, V&& value);
```

Appends `value` as a new last element of `array`. A [null](../basic_json_view/is_null.md) `array` first becomes an
empty array, the same way [`set`](set.md) turns a null `object` into an empty object.

`value` is accepted three ways: a [`basic_json_view`](../basic_json_view/index.md) of *any* document -- read-only or
editable, and it does not have to be `array`'s own document -- which is copied so that nothing is shared with the
source document afterward; a `BasicJsonType` value; or anything `BasicJsonType` can be constructed from (numbers,
strings, `#!cpp bool`, `#!cpp nullptr`, containers, ...).

Only an **editable** document (`#!cpp Editable == true`, e.g. [`json_editable_document`](../json_editable_document.md))
has `push_back`; calling it on a read-only `basic_json_document` fails to compile (`#!cpp static_assert`).

## Template parameters

`V`
:   the type of `value`, deduced; see above for what is accepted.

## Parameters

`array` (in)
:   the array (or null value) to append to

`value` (in)
:   the value to append

## Return value

a view of the new last element of `array`, now holding `value`

## Exception safety

Basic exception safety: `value` is fully encoded -- including the checks below -- into storage owned by the document
before anything already reachable from [`root()`](root.md) is touched, so a failure while encoding `value` (an
invalid argument, or `#!cpp std::bad_alloc`) leaves the document completely unchanged, other than memory allocated
for the encoding that is not reclaimed. A failure of a later allocation -- while `array` switches from its parsed
layout to a growable block, or while that block grows, see [Notes](#notes) -- can still leave a partial effect, such
as a null `array` argument already turned into an empty array even though `value` itself was not appended.

## Exceptions

Throws [`type_error.308`](../../home/exceptions.md#jsonexceptiontype_error308) if `array` is neither an array nor
null -- the same message [`BasicJsonType::push_back`](../basic_json/push_back.md) throws for the same type. Throws
[`invalid_iterator.202`](../../home/exceptions.md#jsonexceptioninvalid_iterator202) ("view does not belong to this
document") if `array` is a [discarded](../basic_json_view/is_discarded.md) view or a view of a *different* document.
Throws [`type_error.302`](../../home/exceptions.md#jsonexceptiontype_error302) if `value` is a
[discarded](../basic_json_view/is_discarded.md) view or a [discarded](../basic_json/is_discarded.md) `BasicJsonType`
value, and [`type_error.319`](../../home/exceptions.md#jsonexceptiontype_error319) if `value` is (or contains) a
binary value -- `BasicJsonType` can hold one, but a `json_document` cannot. Throws
[`type_error.316`](../../home/exceptions.md#jsonexceptiontype_error316) if `value` is (or contains) a string that is
not valid UTF-8, with the same message [`BasicJsonType::dump()`](../basic_json/dump.md) gives for that string.

## Complexity

Amortized constant, plus time linear in the size of `value` to encode it into the document's storage (constant for
a scalar, linear in the number of nested values for an array or object): the elements of `array` move to a growable
block of links the first time it is appended to (or [`set`](set.md) on), and that block itself grows -- doubling its
capacity, so the cost of growing it amortizes to constant per element -- only once it runs out of room. See
[Notes](#notes).

## Notes

Like [`set`](set.md) on a member or an element, `push_back` never moves an existing element itself -- only where
`array`'s *links* to its elements live -- so a view of an existing element of `array` stays valid across a
`push_back`, but any iterator already taken over `array` is invalidated, since it was walking the old layout. See
[Edits](index.md#edits) for what stays valid across an edit in general.

## Examples

??? example

    The example below appends records to an array one at a time, as they might arrive from a stream of events,
    without ever building a `BasicJsonType` value for the array or for the records already in it, and shows that a
    view taken from an earlier `push_back` still refers to the same element once later ones have run.

    ```cpp
    --8<-- "examples/basic_json_document__push_back.cpp"
    ```

    Output:

    ```json
    --8<-- "examples/basic_json_document__push_back.output"
    ```

## See also

- [set](set.md) - replace a value, or set an object member, an array element, or the value a JSON pointer refers to
- [insert](insert.md) - insert an element into an array before a given position
- [erase](erase.md) - remove an object member, an array element, or the value a JSON pointer refers to
- [root](root.md) - the view of the root value
- [`BasicJsonType::push_back`](../basic_json/push_back.md) - the corresponding function of `basic_json`
- [Edits](index.md#edits) - what an edit guarantees, for every overload

## Version history

- Added in version 3.13.0.
