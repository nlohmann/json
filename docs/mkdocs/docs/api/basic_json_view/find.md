# <small>nlohmann::basic_json_view::</small>find

```cpp
iterator find(string_view_t key) const;
iterator find(const char* key) const;
iterator find(const string_t& key) const;
```

Finds a member with key `key` -- the first one, should the key occur more than once (see
[Notes on duplicate keys](operator[].md#notes)). If the value is not an object, or no member has this key,
[`end()`](end.md) is returned.

## Parameters

`key` (in)
:   key value of the element to search for

## Return value

An iterator to the member with key `key`, or [`end()`](end.md) if there is none or the value is not an object.

## Exception safety

No-throw guarantee: this function never throws exceptions.

## Complexity

Linear in the number of members: as for [`ordered_json`](../ordered_json.md), members are compared one after
another, in document order, stopping at the first match. Each comparison first checks the key's length -- already
known from the index, without reading the key bytes -- before comparing its content.
Objects with 128 or more members get a hash index while parsing, so that a lookup in them takes constant time on
average.

## Notes

Unlike [`BasicJsonType::find`](../basic_json/find.md), which always returns `#!cpp end()` for a non-object type, this
also does so for a [discarded](is_discarded.md) view -- there is no separate "invalid" iterator to return.

## Examples

??? example

    The example below scans a batch of events for those that carry an optional `user_id` field, using `find()`
    instead of [`operator[]`](operator[].md) (which would throw for the events that are not objects at all) or
    [`contains()`](contains.md) followed by a second lookup. Events without a match are never materialized.

    ```cpp
    --8<-- "examples/basic_json_view__find.cpp"
    ```

    Output:

    ```json
    --8<-- "examples/basic_json_view__find.output"
    ```

## See also

- [count](count.md) - returns the number of occurrences of a key
- [contains](contains.md) - checks whether a key exists
- [`BasicJsonType::find`](../basic_json/find.md) - the corresponding function of `basic_json`

## Version history

- Added in version 3.13.0.
