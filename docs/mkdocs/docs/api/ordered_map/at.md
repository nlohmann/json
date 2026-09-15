# <small>nlohmann::ordered_map::</small>at

```cpp
// (1)
T& at(const key_type& key);
const T& at(const key_type& key) const;

// (2)
template<class KeyType>
T& at(KeyType&& key);
template<class KeyType>
const T& at(KeyType&& key) const;
```

1. Returns a reference to the value mapped to `key`.
2. Same as (1), but for any `KeyType` comparable to `key_type` via [`key_compare`](key_compare.md)
   (heterogeneous lookup, e.g. looking up by a `#!cpp const char*` without constructing a temporary
   `key_type`). Only participates in overload resolution if `KeyType` is usable as a key type.

## Template parameters

`KeyType`
:   a type comparable to `key_type` via [`key_compare`](key_compare.md)

## Parameters

`key` (in)
:   key of the element to find

## Return value

reference to the mapped value of the element with key equal to `key`

## Exceptions

Throws `std::out_of_range` if no element with key `key` exists.

## Complexity

Linear in the number of elements.

## Examples

??? example

    The example shows how `at` is used.

    ```cpp
    --8<-- "examples/ordered_map__at.cpp"
    ```

    Output:

    ```
    --8<-- "examples/ordered_map__at.output"
    ```

## Version history

- Added in version 3.9.1 to implement [`nlohmann::ordered_json`](../ordered_json.md).
- Overload (2) added in version 3.11.0.
