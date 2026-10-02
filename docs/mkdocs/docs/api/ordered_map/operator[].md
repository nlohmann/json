# <small>nlohmann::ordered_map::</small>operator[]

```cpp
// (1)
T& operator[](const key_type& key);
const T& operator[](const key_type& key) const;

// (2)
template<class KeyType>
T& operator[](KeyType&& key);
template<class KeyType>
const T& operator[](KeyType&& key) const;
```

1. Returns a reference to the value mapped to `key`, inserting a default-constructed `T` (non-`const`
   overload only) if no such element exists yet.
2. Same as (1), but for any `KeyType` comparable to `key_type` via [`key_compare`](key_compare.md)
   (heterogeneous lookup). Only participates in overload resolution if `KeyType` is usable as a key type.

## Template parameters

`KeyType`
:   a type comparable to `key_type` via [`key_compare`](key_compare.md)

## Parameters

`key` (in)
:   key of the element to find or insert

## Return value

reference to the mapped value of the element with key equal to `key`

## Exceptions

The `const` overloads throw `std::out_of_range` if no element with key `key` exists (they delegate to
[`at`](at.md)).

## Complexity

Linear in the number of elements.

## Examples

??? example

    The example shows how `operator[]` is used.

    ```cpp
    --8<-- "examples/ordered_map__operator_idx.cpp"
    ```

    Output:

    ```
    --8<-- "examples/ordered_map__operator_idx.output"
    ```

## Version history

- Added in version 3.9.0 to implement [`nlohmann::ordered_json`](../ordered_json.md).
- Overload (2) added in version 3.11.0.
