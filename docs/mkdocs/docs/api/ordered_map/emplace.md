# <small>nlohmann::ordered_map::</small>emplace

```cpp
// (1)
std::pair<iterator, bool> emplace(const key_type& key, T&& t);

// (2)
template<class KeyType>
std::pair<iterator, bool> emplace(KeyType&& key, T&& t);
```

1. Inserts `#!cpp {key, t}` if no element with an equal key already exists (per [`key_compare`](key_compare.md)),
   appending it at the end to preserve insertion order. If an equal key already exists, does nothing.
2. Same as (1), but for any `KeyType` comparable to `key_type` via [`key_compare`](key_compare.md)
   (heterogeneous lookup). Only participates in overload resolution if `KeyType` is usable as a key type.

## Template parameters

`KeyType`
:   a type comparable to `key_type` via [`key_compare`](key_compare.md)

## Parameters

`key` (in)
:   key of the element to insert

`t` (in)
:   value of the element to insert

## Return value

pair of an iterator to the (possibly newly inserted) element, and a `bool` that is `true` if insertion
took place and `false` if an element with an equal key already existed

## Complexity

Linear in the number of elements.

## Examples

??? example

    The example shows how `emplace` is used.

    ```cpp
    --8<-- "examples/ordered_map__emplace.cpp"
    ```

    Output:

    ```
    --8<-- "examples/ordered_map__emplace.output"
    ```

## Version history

- Added in version 3.9.0 to implement [`nlohmann::ordered_json`](../ordered_json.md).
- Overload (2) added in version 3.11.0.
