# <small>nlohmann::basic_json_view::</small>operator[]

```cpp
// (1)
basic_json_view operator[](string_view_t key) const;
basic_json_view operator[](const char* key) const;
basic_json_view operator[](const string_t& key) const;

// (2)
basic_json_view operator[](size_type idx) const;
basic_json_view operator[](int idx) const;

// (3)
basic_json_view operator[](const json_pointer& ptr) const;
```

1. Returns the value of the object member with key `key` -- the first one, should the key occur more than once (see
   the [Notes](#notes) below) -- or a [discarded](is_discarded.md) view if there is no such member.
2. Returns the array element at index `idx`, or a [discarded](is_discarded.md) view if `idx` is out of range. (The
   `#!cpp int` overload only exists so that an integer literal is not ambiguous between this overload and 1.)
3. Returns the value a JSON pointer `ptr` refers to, starting at this value, or a [discarded](is_discarded.md) view
   wherever resolving it further is not possible without inserting into or extending the document (see
   [Return value](#return-value) and [Exceptions](#exceptions) below).

## Parameters

`key` (in)
:   object key of the element to access

`idx` (in)
:   index of the element to access

`ptr` (in)
:   JSON pointer to the element to access

## Return value

1. the value of the first member with key `key`, or a discarded view if `#!cpp is_object()` is `#!cpp false` or no
   member has this key
2. the element at index `idx`, or a discarded view if `#!cpp is_array()` is `#!cpp false` or `#!cpp idx >= size()`
3. the value `ptr` resolves to, starting at this value, or a discarded view for exactly the reference tokens where the
   **const** overload of [`BasicJsonType::operator[]`](../basic_json/operator%5B%5D.md) invokes undefined behavior for
   the same pointer and the same document: an object member that does not exist, or an array index that is out of
   range

## Exception safety

Strong exception safety: if an exception is thrown, there are no changes to the view or the document it refers to.

## Exceptions

1. Throws [`type_error.305`](../../home/exceptions.md#jsonexceptiontype_error305) if the value is not an object --
   the same exception, with the same message, that the **const** overload of
   [`BasicJsonType::operator[]`](../basic_json/operator%5B%5D.md) throws for a string argument on a non-object value.
2. Throws [`type_error.305`](../../home/exceptions.md#jsonexceptiontype_error305) if the value is not an array --
   the same exception, with the same message, that the **const** overload of
   [`BasicJsonType::operator[]`](../basic_json/operator%5B%5D.md) throws for a numeric argument on a non-array value.
3. Throws the same exceptions, with the same messages, that the **const** overload of
   [`BasicJsonType::operator[]`](../basic_json/operator%5B%5D.md) throws for the same pointer and the same document:
    - [`out_of_range.402`](../../home/exceptions.md#jsonexceptionout_of_range402) if a reference token is `#!cpp "-"`
      at an array.
    - [`out_of_range.404`](../../home/exceptions.md#jsonexceptionout_of_range404) if a reference token cannot be
      resolved because it is used on a primitive value.
    - [`parse_error.106`](../../home/exceptions.md#jsonexceptionparse_error106) if an array index in `ptr` begins
      with `#!cpp '0'`.
    - [`parse_error.109`](../../home/exceptions.md#jsonexceptionparse_error109) if an array index in `ptr` is not a
      number.

None of these exceptions carry a [`JSON_DIAGNOSTICS`](../macros/json_diagnostics.md) path: the view has no
`BasicJsonType` value to point at, so the exception is created without one, even if `BasicJsonType` was built with
`JSON_DIAGNOSTICS` enabled.

## Complexity

1. Linear in the number of members: as for [`ordered_json`](../ordered_json.md), members are compared one after
   another, in document order, stopping at the first match. Each comparison first checks the key's length --
   already known from the index, without reading the key bytes -- before comparing its content, so a key of a
   different length than `key` is rejected without touching the source text.
   Objects with 128 or more members get a hash index while parsing, so that a lookup in them takes constant time
   on average.
2. Linear in `idx`: elements are skipped one at a time from the first one, since they are not a fixed size in the
   index (unlike `BasicJsonType`'s array, which is random-access).
3. Linear in the number of reference tokens of `ptr` and, for each token, in the number of members of the object at
   that level (as 1.) or the index into the array (as 2.).

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

!!! info "JSON pointer resolution"

    Overload 3 walks `ptr` one reference token at a time, starting at this value, the same way [`at`](at.md) and
    [`contains`](contains.md) do. It only ever returns a discarded view where the **const** overload of
    `BasicJsonType::operator[]` would be undefined behavior for the same pointer -- a missing object member or an
    out-of-range array index -- and still throws for every other way `ptr` can fail to resolve. See
    [`at`](at.md#exceptions) for the checked version, which throws in every case instead, and
    [`contains`](contains.md) for a version that never throws.

## Examples

??? example "Example: (1)/(2) access specified element"

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

??? example "Example: (3) access specified element via JSON pointer"

    The example below reaches straight into one deeply nested field of a large document with a single JSON pointer,
    without ever building a tree for the rest of it, and shows the discarded-view and throwing outcomes of a pointer
    that cannot be fully resolved.

    ```cpp
    --8<-- "examples/basic_json_view__operator[]_json_pointer.cpp"
    ```

    Output:

    ```json
    --8<-- "examples/basic_json_view__operator[]_json_pointer.output"
    ```

## See also

- [at](at.md) - access specified element with bounds checking (throws instead of returning a discarded view)
- [front](front.md), [back](back.md) - access the first or last element
- [find](find.md), [contains](contains.md) - look up a member without throwing
- [`BasicJsonType::operator[]`](../basic_json/operator%5B%5D.md) - the corresponding function of `basic_json`
- [`json_pointer`](../json_pointer/index.md) - JSON pointer type used by overload 3

## Version history

- Added in version 3.13.0.
