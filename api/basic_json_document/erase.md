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
3. Removes the value the JSON pointer `ptr` refers to, relative to [`root()`](root.md). `ptr` must not be empty
   ([`root()`](root.md) itself cannot be erased), and the *parent* of the target must already exist. The target is
   removed as in 1. if the parent is an object (returns the number of removed members, `#!cpp 0` or more) and as in 2.
   if it is an array (always returns `#!cpp 1`).

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

Overloads 1. and 2. also throw [`invalid_iterator.202`](../../home/exceptions.md#jsonexceptioninvalid_iterator202)
("view does not belong to this document") if `object`/`array` is a [discarded](../basic_json_view/is_discarded.md)
view or a view of a *different* document. Overload 3. never throws `invalid_iterator.202`: it takes no view, and it
always starts from this document's own [`root()`](root.md).

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
longer appears when `array`/`object` is read, dumped, or iterated. What does change is the container's sequence of
*links* to its elements: removing an element of `array` (2.) shifts the links to the elements after it by one, as
[`insert`](insert.md) does in the other direction. *Every* iterator already taken over `array`/`object` is invalidated
by an erase, not only those at or after the removed element, since the container may now use a different sequence.

## Examples

??? example

    The example below drops a deprecated field and a decommissioned entry from a configuration document -- using all
    three overloads -- and shows what stays intact that would not with a plain `json`/`ordered_json` value: the order
    of the fields around the ones removed, and the exact spelling of a number that was never touched.

    ```cpp
    #include <iostream>
    #include <nlohmann/json_view.hpp>
    
    using json = nlohmann::json;
    using json_editable_document = nlohmann::json_editable_document;
    using json_editable_view = nlohmann::json_editable_view;
    
    int main()
    {
        // a deprecated field is dropped from a configuration file, and a
        // decommissioned replica is removed from the list -- "price" keeps its
        // trailing zero, and the fields around the removed ones keep their order
        const std::string text = R"({
      "name": "cache",
      "legacy_host": "db0",
      "host": "db1",
      "price": 19.90,
      "replicas": ["db2", "db3", "db4"]
    })";
    
        json_editable_document doc = json_editable_document::parse(text);
    
        doc.erase(doc.root(), "legacy_host");                                      // (1) an object member
        doc.erase(doc.root()["replicas"], 1);                                      // (2) an array element ("db3")
        const std::size_t removed = doc.erase(json::json_pointer("/replicas/0"));  // (3) via a JSON pointer
    
        std::cout << removed << '\n';
        std::cout << doc.root().dump(2, ' ', false, json_editable_view::number_format::source) << "\n\n";
    
        // the same edits on a plain json value: object_t is a std::map, so
        // parsing already sorted the keys, and dump() rewrites every number to
        // its shortest form, even "price", which was never touched
        json plain = json::parse(text);
        plain.erase("legacy_host");
        plain["replicas"].erase(1);
        plain["replicas"].erase(0);
        std::cout << plain.dump(2) << '\n';
    }
    
    ```

    Output:

    ```json
    1
    {
      "name": "cache",
      "host": "db1",
      "price": 19.90,
      "replicas": [
        "db4"
      ]
    }
    
    {
      "host": "db1",
      "name": "cache",
      "price": 19.9,
      "replicas": [
        "db4"
      ]
    }
    
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
