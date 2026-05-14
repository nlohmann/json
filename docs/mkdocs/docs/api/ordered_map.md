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
