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

When the storage grows, the keys are copied and the mapped values are moved to the new storage. A plain `std::vector`
would copy the whole elements instead, because their `#!cpp const` keys make them not nothrow move constructible; for
[`ordered_json`](ordered_json.md), this would be a deep copy of every nested value. The values are only copied if
`T` is not default constructible or not nothrow move assignable.

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

## Exception safety

**emplace**, **operator\[\]**, and **insert(value)** have the strong exception guarantee: if an exception is thrown (for
instance, because copying a key or allocating memory fails), the contents of the container are unchanged.

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
    **O(n²)** in total. This applies to filling an [`ordered_json`](ordered_json.md) object key by key (with
    `operator[]`, `emplace`, or `insert`) and, for now, to reading one with a binary reader such as
    [`from_cbor`](basic_json/from_cbor.md) ([#6104](https://github.com/nlohmann/json/issues/6104)). Parsing JSON text
    is not affected: the parser finds the keys of an object with many members in a hash table and takes linear time.

    The cost is negligible for the object sizes typically found in configuration files or API payloads, but it grows
    steeply for machine-generated objects with many thousands of keys. Measured with Apple clang 21, `-O2 -DNDEBUG`,
    arm64, for a flat object of `n` keys (best of seven runs):

    | `n`    | `json::parse` | `ordered_json::parse` | `ordered_json`, key by key | `ordered_json::from_cbor` |
    |--------|---------------|-----------------------|----------------------------|---------------------------|
    | 2000   | 0.3 ms        | 0.1 ms                | 4.5 ms                     | 4.4 ms                    |
    | 4000   | 0.5 ms        | 0.2 ms                | 17.1 ms                    | 16.8 ms                   |
    | 8000   | 0.9 ms        | 0.3 ms                | 67.0 ms                    | 66.8 ms                   |
    | 16 000 | 2.0 ms        | 0.7 ms                | 282.4 ms                   | 282.4 ms                  |

    If key order matters for objects of that size, consider a container with a lookup index, such as
    [`nlohmann::fifo_map`](https://github.com/nlohmann/fifo_map)
    ([integration](https://github.com/nlohmann/json/issues/485#issuecomment-333652309)), as the object type — see
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

- [`ordered_json`](ordered_json.md) - JSON specialization preserving insertion order
- [Object Order](../features/object_order.md) - the article on object key order

## Version history

- Added in version 3.9.0 to implement [`nlohmann::ordered_json`](ordered_json.md).
- Added **key_compare** member in version 3.11.0.
- Changed in version 3.13.0: growing the storage moves the mapped values instead of copying them.
