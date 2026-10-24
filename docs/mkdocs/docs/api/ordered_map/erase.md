# <small>nlohmann::ordered_map::</small>erase

```cpp
// (1)
size_type erase(const key_type& key);

// (2)
template<class KeyType>
size_type erase(KeyType&& key);

// (3)
iterator erase(iterator pos);

// (4)
iterator erase(iterator first, iterator last);
```

1. Removes the element with key equal to `key`, if any, preserving the relative order of the remaining
   elements.
2. Same as (1), but for any `KeyType` comparable to `key_type` via [`key_compare`](key_compare.md)
   (heterogeneous lookup). Only participates in overload resolution if `KeyType` is usable as a key type.
3. Removes the element at `pos`.
4. Removes the elements in range `[first, last)`.

## Template parameters

`KeyType`
:   a type comparable to `key_type` via [`key_compare`](key_compare.md)

## Parameters

`key` (in)
:   key of the element to remove

`pos` (in)
:   iterator to the element to remove

`first` (in)
:   iterator to the first element to remove

`last` (in)
:   iterator one past the last element to remove

## Return value

1. number of elements removed (0 or 1)
2. number of elements removed (0 or 1)
3. iterator following the removed element
4. iterator following the last removed element

## Complexity

Linear in the number of elements (elements after the removed one(s) are shifted to keep storage
contiguous).

## Examples

??? example

    The example shows how `erase` is used.

    ```cpp
    --8<-- "examples/ordered_map__erase.cpp"
    ```

    Output:

    ```
    --8<-- "examples/ordered_map__erase.output"
    ```

## Version history

- Added in version 3.9.0 to implement [`nlohmann::ordered_json`](../ordered_json.md).
- Overload (2) added in version 3.11.0.
