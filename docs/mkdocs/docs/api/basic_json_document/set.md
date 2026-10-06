# <small>nlohmann::basic_json_document::</small>set

```cpp
// (1)
template<typename V>
view_type set(view_type target, V&& value);

// (2)
template<typename V>
view_type set(view_type object, string_view_t key, V&& value);

// (3)
template<typename I, typename V>
view_type set(view_type array, I idx, V&& value);

// (4)
template<typename V>
view_type set(const json_pointer& ptr, V&& value);
```

Only an **editable** document (`#!cpp Editable == true`, e.g. [`json_editable_document`](../json_editable_document.md))
has `set`; calling it on a read-only `basic_json_document` fails to compile (`#!cpp static_assert`).

1. Replaces the value `target` refers to with `value`.
2. Sets the member `key` of the object `object` to `value`: assigns it if `object` already has a member with this
   key -- the first one, should the key occur more than once, and the later duplicates are then dropped (see the
   [Notes](#notes) below) -- or appends a new member at the end otherwise. A [null](../basic_json_view/is_null.md)
   `object` first becomes an empty object.
3. Assigns `value` to the element at index `idx` of the array `array`, which must already exist (`#!cpp idx <
   array.size()`).
4. Sets the value the JSON pointer `ptr` refers to, relative to [`root()`](root.md), to `value`. The *parent* of the
   target must already exist: an object member is set as in 2. (added if it does not exist yet), an array element is
   assigned as in 3., and a last reference token of `#!cpp "-"`, or equal to the size of the array, appends `value`
   instead, exactly as [`push_back`](push_back.md) would. An empty `ptr` sets [`root()`](root.md) itself, as in 1.

In every overload, `value` is accepted three ways: a [`basic_json_view`](../basic_json_view/index.md) of *any*
document -- read-only or editable, and it does not have to be `target`'s/`object`'s/`array`'s own document -- which
is copied so that nothing is shared with the source document afterward; a `BasicJsonType` value; or anything
`BasicJsonType` can be constructed from (numbers, strings, `#!cpp bool`, `#!cpp nullptr`, containers, ...).

## Template parameters

`V`
:   the type of `value`, deduced; see above for what is accepted.

`I`
:   an integral type other than `#!cpp bool`, deduced (overloads taking a `#!cpp bool` or a non-integral type for
    `idx` do not participate in overload resolution).

## Parameters

`target` (in)
:   the value to replace

`object` (in)
:   the object (or null value) whose member to set

`array` (in)
:   the array whose element to assign

`key` (in)
:   the key of the member to set

`idx` (in)
:   the index of the element to assign; a negative value throws (see [Exceptions](#exceptions))

`ptr` (in)
:   a JSON pointer to the value to set, relative to `root()`

`value` (in)
:   the new value

## Return value

1. a view of `target`, now holding `value`
2. a view of the member `key` of `object`, now holding `value`
3. a view of the element `idx` of `array`, now holding `value`
4. a view of the value `ptr` refers to, now holding `value`

## Exception safety

Basic exception safety: `value` is fully encoded -- including the checks below -- into storage owned by the document
before anything already reachable from [`root()`](root.md) is touched, so a failure while encoding `value` (an
invalid argument, or `#!cpp std::bad_alloc`) leaves the document completely unchanged, other than memory allocated
for the encoding that is not reclaimed. A failure of a later allocation -- while an edited array or object switches
from its parsed layout to a growable block, see [Notes](#notes) -- can still leave a partial effect, such as a
[null](../basic_json_view/is_null.md) `object`/`array` argument already turned into an empty object/array even
though `value` itself was not linked in.

## Exceptions

1. Throws [`type_error.302`](../../home/exceptions.md#jsonexceptiontype_error302) if `value` is a
   [discarded](../basic_json_view/is_discarded.md) view, or a [discarded](../basic_json/is_discarded.md)
   `BasicJsonType` value (e.g. `#!cpp BasicJsonType(value_t::discarded)`) -- an object or array `value`, of either
   kind, is fine and is encoded as a whole subtree.
2. Throws [`type_error.305`](../../home/exceptions.md#jsonexceptiontype_error305) if `object` is neither an object
   nor null -- the same message [`operator[]`](../basic_json_view/operator%5B%5D.md) throws for a string argument on
   such a value. Throws [`type_error.316`](../../home/exceptions.md#jsonexceptiontype_error316) if `key` is not
   valid UTF-8, with the same message [`BasicJsonType::dump()`](../basic_json/dump.md) gives for that string.
   Also throws what 1. throws for `value`.
3. Throws `type_error.305` if `array` is not an array -- the same message `operator[]` throws for a numeric argument
   on such a value. Throws [`out_of_range.401`](../../home/exceptions.md#jsonexceptionout_of_range401) if `idx` is
   negative, or if `#!cpp idx >= array.size()`. Also throws what 1. throws for `value`.
4. Throws what [`at`](../basic_json_view/at.md) throws (overload 3) for resolving `ptr`'s parent, except that a
   missing object member or an array index equal to the array's size at the very last reference token is not an
   error there (it becomes a new member or an appended element) instead of
   [`out_of_range.403`](../../home/exceptions.md#jsonexceptionout_of_range403)/[`out_of_range.402`](../../home/exceptions.md#jsonexceptionout_of_range402).
   For the last reference token itself: if the parent is an object (or a primitive value, where it throws
   `type_error.305`), throws what 2. throws; if the parent is an array, throws what 3. throws for an index that is
   out of range, or, for a token that is not a valid array index,
   [`parse_error.106`](../../home/exceptions.md#jsonexceptionparse_error106) (a leading `#!cpp '0'`),
   [`parse_error.109`](../../home/exceptions.md#jsonexceptionparse_error109) (not a number),
   [`out_of_range.410`](../../home/exceptions.md#jsonexceptionout_of_range410) (too large for `size_type`), or
   [`out_of_range.404`](../../home/exceptions.md#jsonexceptionout_of_range404) (an empty token). Also throws what 1.
   throws for `value`.

Every overload also throws [`type_error.319`](../../home/exceptions.md#jsonexceptiontype_error319) if `value` is (or
contains) a binary value -- `BasicJsonType` can hold one, but a `json_document` cannot -- and
[`invalid_iterator.202`](../../home/exceptions.md#jsonexceptioninvalid_iterator202) ("view does not belong to this
document") if `target`/`object`/`array` is a [discarded](../basic_json_view/is_discarded.md) view or a view of a
*different* document (overloads 1-3 only; overload 4 always starts from this document's own [`root()`](root.md)).

## Complexity

1. Linear in the size of `value` (encoding it into the document's storage): constant for a scalar, linear in the
   number of nested values for an array or object. If `target` is itself an array or object that spans more than one
   node in its parent's original, unedited layout, and `value` is a scalar, replacing it additionally costs time
   linear in the number of elements of that parent, the *first* time -- see [Notes](#notes).
2. Linear in the number of members of `object`, to find an existing member with `key`, plus the complexity of 1. for
   `value`.
3. Constant, plus the complexity of 1. for `value`.
4. Linear in the number of reference tokens of `ptr` and, for each token, in the number of members of the object at
   that level or the index into the array (as [`at`](../basic_json_view/at.md)), plus the complexity of 2. or 3. for
   the last token.

## Notes

!!! info "Duplicate keys"

    If `object` already has more than one member with `key` (2.), the *first* one is assigned `value` and every
    later member with the same key is removed -- so that a lookup, an iteration, and
    [`materialize()`](../basic_json_view/materialize.md) of `object` afterward all agree on a single value for
    `key`, the same way [`operator[]`](../basic_json_view/operator%5B%5D.md) already picks the first occurrence of a
    duplicate key for reading. See the [Notes on duplicate keys](../basic_json_view/operator%5B%5D.md#notes) of
    `operator[]`.

Setting a member (2.) or an element (3., through 4.) of an array or object whose elements have not been edited
before switches it from its parsed layout to a growable block holding links to its elements; a later
[`push_back`](push_back.md) or `set` on the same container reuses that block, growing it (amortized constant time)
only once it runs out of room. This never moves an element itself -- only where the container's *links* to its
elements live -- so a view of an element stays valid, but any iterator already taken over the container is
invalidated, since it was walking the old layout. See [Edits](index.md#edits) for what stays valid across an edit in
general.

The same switch happens, for the same reason, when overload 1. replaces a multi-node array/object value with a
scalar: the *parent's* element sequence is what has to switch to links, not `target` itself, because the parent
originally stepped over `target`'s whole subtree by its node count, which no longer applies once `target` is a
one-node scalar.

## Examples

??? example "Example: (1)/(2)/(3)/(4) replace a value, set a member, assign an element, set via a JSON pointer"

    The example below edits a small configuration document -- replacing a value, adding an object member, assigning
    an array element, and reaching a field through a JSON pointer -- and shows what
    [`dump()`](../basic_json_view/dump.md) preserves that is lost once the same edits are made on a `BasicJsonType`
    value instead: the order object members were written in, and the exact spelling of a number that was never
    touched.

    ```cpp
    --8<-- "examples/basic_json_document__set.cpp"
    ```

    Output:

    ```json
    --8<-- "examples/basic_json_document__set.output"
    ```

## See also

- [push_back](push_back.md) - append to an array
- [insert](insert.md) - insert an element into an array
- [erase](erase.md) - remove an object member, an array element, or the value a JSON pointer refers to
- [root](root.md) - the view of the root value, the starting point of overload 4
- [`basic_json_view::dump`](../basic_json_view/dump.md) - serialize the document, keeping an untouched number's
  spelling with `#!cpp number_format::source`
- [Edits](index.md#edits) - what an edit guarantees, for every overload
- [Editing a document](../../features/json_view.md#editing-a-document) - why editable documents keep the source
  text's order and number spelling

## Version history

- Added in version 3.13.0.
