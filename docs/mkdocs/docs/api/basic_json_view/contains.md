# <small>nlohmann::basic_json_view::</small>contains

```cpp
bool contains(string_view_t key) const;
bool contains(const char* key) const;
bool contains(const string_t& key) const;
```

Checks whether the value is an object with a member with key `key`.

## Parameters

`key` (in)
:   key value to check its existence

## Return value

`#!cpp true` if the value is an object and has a member with key `key`, `#!cpp false` otherwise.

## Exception safety

No-throw guarantee: this function never throws exceptions.

## Complexity

Linear in the number of members: as for [`ordered_json`](../ordered_json.md), members are compared one after
another, in document order, stopping at the first match. Each comparison first checks the key's length -- already
known from the index, without reading the key bytes -- before comparing its content.

## Notes

This method always returns `#!cpp false` when the value is not an object -- including a [discarded](is_discarded.md)
view.

!!! info "Postconditions"

    If `#!cpp v.contains(key)` returns `#!cpp true`, then `#!cpp v[key]` is not [discarded](is_discarded.md).

## Examples

??? example

    The example below counts how many of a batch of records carry an optional `retry_of` field, using `contains()`
    to check without ever materializing a single record of the batch.

    ```cpp
    --8<-- "examples/basic_json_view__contains.cpp"
    ```

    Output:

    ```json
    --8<-- "examples/basic_json_view__contains.output"
    ```

## See also

- [find](find.md) - find a value in an object
- [count](count.md) - returns the number of occurrences of a key
- [`BasicJsonType::contains`](../basic_json/contains.md) - the corresponding function of `basic_json`

## Version history

- Added in version 3.13.0.
