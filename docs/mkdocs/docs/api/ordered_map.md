# <small>nlohmann::</small>ordered_map

```cpp
template<class Key, class T, class IgnoredLess = std::less<Key>,
         class Allocator = std::allocator<std::pair<const Key, T>>>
struct ordered_map : std::vector<std::pair<const Key, T>, Allocator>;
```

A minimal map-like container that preserves insertion order for use within [`nlohmann::ordered_json`](ordered_json.md)
(`nlohmann::basic_json<ordered_map>`).

## Template parameters

`Key`
:   key type

`T`
:   mapped type

`IgnoredLess`
:   comparison function (ignored and only added to ensure compatibility with `#!cpp std::map`)

`Allocator`
:   allocator type

## Iterator invalidation

The type uses a `std::vector` to store object elements. Therefore, adding elements can yield a reallocation in which
case all iterators (including the `end()` iterator) and all references to the elements are invalidated.

## Member types

- **key_type** - key type (`Key`)
- **mapped_type** - mapped type (`T`)
- **Container** - base container type (`#!cpp std::vector<std::pair<const Key, T>, Allocator>`)
- **iterator**
- **const_iterator**
- **size_type**
- **value_type**
- **key_compare** - key comparison function
```cpp
std::equal_to<Key>  // until C++14

std::equal_to<>     // since C++14
```

## Member functions

- (constructor)
- (destructor)
- **emplace**
- **operator\[\]**
- **at**
- **erase**
- **count**
- **find**
- **insert**

## Complexity

Because the elements are stored in a `std::vector` in insertion order, there is no index to look a key up by. Every
key-based operation performs a **linear scan** over the stored elements. With `n` denoting the number of elements in the
container:

| Operation                              | Complexity     | Note                                                     |
|----------------------------------------|----------------|----------------------------------------------------------|
| **emplace**                            | O(n)           | scans for an existing key, then appends (amortized O(1)) |
| **operator\[\]**                       | O(n)           | delegates to **emplace** (non-const) or **at** (const)   |
| **at**                                 | O(n)           | throws `#!cpp std::out_of_range` if the key is not found |
| **find**                               | O(n)           |                                                          |
| **count**                              | O(n)           | the result is always 0 or 1                              |
| **erase(key)**                         | O(n)           | scan, then move the remaining elements one position down |
| **erase(pos)**, **erase(first, last)** | O(n)           | moves all elements after the erased range                |
| **insert(value)**                      | O(n)           | equivalent to **emplace**                                |
| **insert(first, last)**                | O((n + m) * m) | for `m` inserted elements                                |

This differs from `#!cpp std::map`, where the same operations are O(log n).

!!! warning "Quadratic cost of building large objects"

    Because every insertion scans all elements inserted so far, building an object of `n` distinct keys costs
    **O(n²)** in total. This applies to filling an [`ordered_json`](ordered_json.md) object key by key as well as to
    parsing one, since the parser inserts each key as it is read.

    The cost is negligible for the object sizes typically found in configuration files or API payloads, but it grows
    steeply for machine-generated objects with many thousands of keys. Measured with `-O2 -DNDEBUG` for parsing a flat
    object of `n` keys, relative to `#!cpp nlohmann::json` (which uses `#!cpp std::map`):

    | `n`    | `json` | `ordered_json` | factor |
    |--------|--------|----------------|--------|
    | 2000   | 0.7 ms | 3.6 ms         | 5×     |
    | 4000   | 0.8 ms | 14.0 ms        | 19×    |
    | 8000   | 1.6 ms | 67.8 ms        | 43×    |
    | 16 000 | 3.3 ms | 181.6 ms       | 54×    |

    If key order matters for objects of that size, consider a container with a lookup index, such as
    [`tsl::ordered_map`](https://github.com/Tessil/ordered-map)
    ([integration](https://github.com/nlohmann/json/issues/546#issuecomment-304447518)), as the object type -- see
    [object order](../features/object_order.md).

## Examples

??? example

    The example shows the different behavior of `std::map` and `nlohmann::ordered_map`.
     
    ```cpp
    --8<-- "examples/ordered_map.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/ordered_map.output"
    ```

## See also

- [ordered_json](ordered_json.md)

## Version history

- Added in version 3.9.0 to implement [`nlohmann::ordered_json`](ordered_json.md).
- Added **key_compare** member in version 3.11.0.
