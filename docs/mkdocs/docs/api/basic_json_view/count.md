# <small>nlohmann::basic_json_view::</small>count

```cpp
size_type count(string_view_t key) const;
size_type count(const char* key) const;
size_type count(const string_t& key) const;
```

Returns `#!cpp 1` if the value is an object with a member with key `key`, `#!cpp 0` otherwise.

## Parameters

`key` (in)
:   key value of the element to count

## Return value

`#!cpp 1` if the value is an object and has a member with key `key`, `#!cpp 0` otherwise.

## Exception safety

No-throw guarantee: this function never throws exceptions.

## Complexity

Linear in the number of members: as for [`ordered_json`](../ordered_json.md), members are compared one after
another, in document order, stopping at the first match. Each comparison first checks the key's length -- already
known from the index, without reading the key bytes -- before comparing its content.
Objects with 128 or more members get a hash index while parsing, so that a lookup in them takes constant time on
average.

## Notes

This method always returns `#!cpp 0` when the value is not an object -- including a [discarded](is_discarded.md)
view.

Unlike [`BasicJsonType::count()`](../basic_json/count.md), whose return value can in principle exceed `#!cpp 1` for
an `ObjectType` that allows multiple entries per key, `count()` here never does: it is exactly
[`contains()`](contains.md) as `#!cpp 0`/`#!cpp 1`. This holds even if the source text has a duplicate key -- see the
[Notes on duplicate keys](operator[].md#notes) of `operator[]` -- because a `#!cpp count() > 1` result would require
counting every member with a matching key, not just finding the first one.

## Examples

??? example

    The example below validates that every transaction of a batch carries a mandatory `amount` field, using
    `count()` before deciding whether to materialize a transaction at all.

    ```cpp
    --8<-- "examples/basic_json_view__count.cpp"
    ```

    Output:

    ```json
    --8<-- "examples/basic_json_view__count.output"
    ```

## See also

- [find](find.md) - find a value in an object
- [contains](contains.md) - checks whether a key exists
- [`BasicJsonType::count`](../basic_json/count.md) - the corresponding function of `basic_json`

## Version history

- Added in version 3.13.0.
