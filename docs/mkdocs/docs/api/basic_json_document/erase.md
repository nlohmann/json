# <small>nlohmann::basic_json_document::</small>erase

```cpp
// (1)
std::size_t erase(view_type object, string_view_t key);

// (2)
template<typename I>
void erase(view_type array, I idx);

// (3)
std::size_t erase(const json_pointer& ptr);
```

Only an **editable** document (`#!cpp Editable == true`, e.g. [`json_editable_document`](../json_editable_document.md))
has `erase`; calling it on a read-only `basic_json_document` fails to compile (`#!cpp static_assert`).

1. Removes every member of `object` whose key is `key` (see [Notes](#notes) on duplicate keys) and returns how many
   were removed; `#!cpp 0` if `object` has no member with this key.
2. Removes the element at index `idx` of `array`, which must already exist (`#!cpp idx < array.size()`).
3. Removes the value the JSON pointer `ptr` refers to, relative to [`root()`](root.md), and returns how many values
   were removed: the *parent* of the target must already exist, and the target itself is removed as in 1. (an object
   member; `#!cpp 0` or more) or 2. (an array element; always `#!cpp 1`). `ptr` must not be empty -- [`root()`](root.md)
   itself cannot be erased.

## Template parameters

`I`
:   an integral type other than `#!cpp bool`, deduced (overloads taking a `#!cpp bool` or a non-integral type for
    `idx` do not participate in overload resolution).

## Parameters

`object` (in)
:   the object to remove a member of

`array` (in)
:   the array to remove an element of

`key` (in)
:   the key of the member(s) to remove

`idx` (in)
:   the index of the element to remove; a negative value throws (see [Exceptions](#exceptions))

`ptr` (in)
:   a JSON pointer to the value to remove, relative to `root()`

## Return value

1. the number of removed members (`#!cpp 0` if `object` had none with this `key`)
2. (nothing)
3. the number of removed values (`#!cpp 0` or more for an object member, always `#!cpp 1` for an array element)

## Exceptions

1. Throws [`type_error.307`](../../home/exceptions.md#jsonexceptiontype_error307) if `object` is not an object -- the
   same message [`BasicJsonType::erase`](../basic_json/erase.md) throws for the same type.
2. Throws `type_error.307` if `array` is not an array. Throws
   [`out_of_range.401`](../../home/exceptions.md#jsonexceptionout_of_range401) if `idx` is negative, or if
   `#!cpp idx >= array.size()`.
3. Throws [`out_of_range.405`](../../home/exceptions.md#jsonexceptionout_of_range405) ("JSON pointer has no parent")
   if `ptr` is empty. Throws what [`at`](../basic_json_view/at.md) throws (overload 3) for resolving `ptr`'s parent.
   For the last reference token itself: if the parent is an array, throws what 2. throws for an index that is out of
   range, or, for a token that is not a valid array index,
   [`parse_error.106`](../../home/exceptions.md#jsonexceptionparse_error106) (a leading `#!cpp '0'`),
   [`parse_error.109`](../../home/exceptions.md#jsonexceptionparse_error109) (not a number),
   [`out_of_range.410`](../../home/exceptions.md#jsonexceptionout_of_range410) (too large for `size_type`), or
   [`out_of_range.404`](../../home/exceptions.md#jsonexceptionout_of_range404) (an empty token); otherwise (an
   object, or a primitive value the pointer's parent resolves to) throws what 1. throws.

Every overload also throws [`invalid_iterator.202`](../../home/exceptions.md#jsonexceptioninvalid_iterator202) ("view
does not belong to this document") if `object`/`array` is a [discarded](../basic_json_view/is_discarded.md) view or a
view of a *different* document (overloads 1-2 only; overload 3 always starts from this document's own
[`root()`](root.md)).

## Complexity

1. Linear in the number of members of `object`.
2. Linear in the number of elements of `array` at or after `idx` (they move one slot over).
3. Linear in the number of reference tokens of `ptr` and, for each token, in the number of members of the object at
   that level or the index into the array (as [`at`](../basic_json_view/at.md)), plus the complexity of 1. or 2. for
   the last token.

## Notes

!!! info "Duplicate keys"

    Overload 1. removes *every* member with `key`, not just the first -- unlike [`set`](set.md), which assigns the
    first occurrence and drops the rest. This is why it returns a count rather than a single view: there may be
    more than one member removed, or none.

Like [`set`](set.md) and [`push_back`](push_back.md), `erase` never moves an element's *value*: a view still
referring to a removed member or element keeps showing what it last held (see [Edits](index.md#edits)) -- it just no
longer appears when `array`/`object` is read, dumped, or iterated. Removing an element of `array` (2.) does shift the
*links* to the elements after it, the same way `insert`, `set`, or `push_back` on the same array would; any iterator
already taken over `array`/`object` is invalidated by an erase, since it was walking the old layout.

## Examples

??? example

    The example below drops a deprecated field and a decommissioned entry from a configuration document -- using all
    three overloads -- and shows what stays intact that would not with a plain `json`/`ordered_json` value: the order
    of the fields around the ones removed, and the exact spelling of a number that was never touched.

    ```cpp
    --8<-- "examples/basic_json_document__erase.cpp"
    ```

    Output:

    ```json
    --8<-- "examples/basic_json_document__erase.output"
    ```

## See also

- [insert](insert.md) - insert an element into an array
- [set](set.md) - replace a value, or set an object member, an array element, or the value a JSON pointer refers to
- [push_back](push_back.md) - append to an array
- [root](root.md) - the view of the root value, the starting point of overload 3
- [`BasicJsonType::erase`](../basic_json/erase.md) - the corresponding function of `basic_json`
- [Edits](index.md#edits) - what an edit guarantees, for every overload

## Version history

- Added in version 3.13.0.
