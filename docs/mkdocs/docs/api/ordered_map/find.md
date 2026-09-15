# <small>nlohmann::ordered_map::</small>find

```cpp
// (1)
iterator find(const key_type& key);
const_iterator find(const key_type& key) const;

// (2)
template<class KeyType>
iterator find(KeyType&& key);
template<class KeyType>
const_iterator find(KeyType&& key) const;
```

1. Returns an iterator to the element with key equal to `key`, or `end()` if no such element exists.
2. Same as (1), but for any `KeyType` comparable to `key_type` via [`key_compare`](key_compare.md)
   (heterogeneous lookup). Only participates in overload resolution if `KeyType` is usable as a key type.

## Template parameters

`KeyType`
:   a type comparable to `key_type` via [`key_compare`](key_compare.md)

## Parameters

`key` (in)
:   key of the element to find

## Return value

iterator to the element with key equal to `key`, or `end()` if not found

## Complexity

Linear in the number of elements.

## Examples

??? example

    The example shows how `find` is used.

    ```cpp
    --8<-- "examples/ordered_map__find.cpp"
    ```

    Output:

    ```
    --8<-- "examples/ordered_map__find.output"
    ```

## Version history

- Added in version 3.9.1 to implement [`nlohmann::ordered_json`](../ordered_json.md).
- Overload (2) added in version 3.11.0.
