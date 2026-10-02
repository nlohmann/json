# <small>nlohmann::basic_json_view::</small>operator[]

```cpp
// (1)
basic_json_view operator[](string_view_t key) const;
basic_json_view operator[](const char* key) const;
basic_json_view operator[](const string_t& key) const;

// (2)
basic_json_view operator[](size_type idx) const;
basic_json_view operator[](int idx) const;
```

1. Returns the value of the object member with key `key` -- the first one, should the key occur more than once (see
   the [Notes](#notes) below) -- or a [discarded](is_discarded.md) view if there is no such member.
2. Returns the array element at index `idx`, or a [discarded](is_discarded.md) view if `idx` is out of range. (The
   `#!cpp int` overload only exists so that an integer literal is not ambiguous between this overload and 1.)

## Parameters

`key` (in)
:   object key of the element to access

`idx` (in)
:   index of the element to access

## Return value

1. the value of the first member with key `key`, or a discarded view if `#!cpp is_object()` is `#!cpp false` or no
   member has this key
2. the element at index `idx`, or a discarded view if `#!cpp is_array()` is `#!cpp false` or `#!cpp idx >= size()`

## Exception safety

Strong exception safety: if an exception is thrown, there are no changes to the view or the document it refers to.

## Exceptions

1. Throws [`type_error.305`](../../home/exceptions.md#jsonexceptiontype_error305) if the value is not an object --
   the same exception, with the same message, that the **const** overload of
   [`BasicJsonType::operator[]`](../basic_json/operator%5B%5D.md) throws for a string argument on a non-object value.
2. Throws [`type_error.305`](../../home/exceptions.md#jsonexceptiontype_error305) if the value is not an array --
   the same exception, with the same message, that the **const** overload of
   [`BasicJsonType::operator[]`](../basic_json/operator%5B%5D.md) throws for a numeric argument on a non-array value.

Neither exception carries a [`JSON_DIAGNOSTICS`](../macros/json_diagnostics.md) path: the view has no `BasicJsonType`
value to point at, so the exception is created without one, even if `BasicJsonType` was built with
`JSON_DIAGNOSTICS` enabled.

## Complexity

1. Linear in the number of members: as for [`ordered_json`](../ordered_json.md), members are compared one after
   another, in document order, stopping at the first match. Each comparison first checks the key's length --
   already known from the index, without reading the key bytes -- before comparing its content, so a key of a
   different length than `key` is rejected without touching the source text.
2. Linear in `idx`: elements are skipped one at a time from the first one, since they are not a fixed size in the
   index (unlike `BasicJsonType`'s array, which is random-access).

## Notes

Unlike `BasicJsonType::operator[]`, which is undefined behavior (guarded by a
[runtime assertion](../../features/assertions.md)) for a missing key on a **const** value, this operator always
returns a safe, testable result: a [discarded](is_discarded.md) view, which is `#!cpp false` in a boolean context.
There is also no non-const overload that inserts a missing key or extends an array -- a view never modifies the
document.

!!! info "Duplicate keys"

    If the source text has an object with a duplicate key, `#!cpp operator[]` (and [`at`](at.md), [`find`](find.md),
    [`contains`](contains.md), [`count`](count.md)) all resolve to the *first* member with that key, because a
    lookup can stop as soon as it finds a match. This is different from
    [`materialize()`](materialize.md) (and [`BasicJsonType::parse()`](../basic_json/parse.md)), which replay every
    member in order and so end up keeping the *last* value for a repeated key -- there is no reason for them to stop
    early. [`begin()`](begin.md)/[`end()`](end.md) and [`items()`](items.md) iterate over *all* members, including
    duplicates, in document order. See the example below and [`size()`](size.md#notes).

## Examples

??? example

    The example below reads a couple of fields out of a batch of user records without ever materializing a full
    `BasicJsonType` value for the batch. `operator[]` is used both to look up an optional object member and to index
    into an array -- in both cases, a missing value comes back as a discarded view that can be tested with a plain
    `#!cpp if`, instead of relying on undefined behavior.

    ```cpp
    --8<-- "examples/basic_json_view__operator[].cpp"
    ```

    Output:

    ```json
    --8<-- "examples/basic_json_view__operator[].output"
    ```

## See also

- [at](at.md) - access specified element with bounds checking (throws instead of returning a discarded view)
- [front](front.md), [back](back.md) - access the first or last element
- [find](find.md), [contains](contains.md) - look up a member without throwing
- [`BasicJsonType::operator[]`](../basic_json/operator%5B%5D.md) - the corresponding function of `basic_json`

## Version history

- Added in version 3.13.0.
