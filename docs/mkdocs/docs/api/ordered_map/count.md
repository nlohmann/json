# <small>nlohmann::ordered_map::</small>count

```cpp
// (1)
size_type count(const key_type& key) const;

// (2)
template<class KeyType>
size_type count(KeyType&& key) const;
```

1. Returns the number of elements with key equal to `key` (0 or 1, since keys are unique).
2. Same as (1), but for any `KeyType` comparable to `key_type` via [`key_compare`](key_compare.md)
   (heterogeneous lookup). Only participates in overload resolution if `KeyType` is usable as a key type.

## Template parameters

`KeyType`
:   a type comparable to `key_type` via [`key_compare`](key_compare.md)

## Parameters

`key` (in)
:   key of the elements to count

## Return value

number of elements with key equal to `key` (0 or 1)

## Complexity

Linear in the number of elements.

## Examples

??? example

    The example shows how `count` is used.

    ```cpp
    --8<-- "examples/ordered_map__count.cpp"
    ```

    Output:

    ```
    --8<-- "examples/ordered_map__count.output"
    ```

## Version history

- Added in version 3.9.1 to implement [`nlohmann::ordered_json`](../ordered_json.md).
- Overload (2) added in version 3.11.0.
