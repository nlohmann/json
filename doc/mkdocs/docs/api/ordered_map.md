# ordered_map

```cpp
template<class Key, class T, class IgnoredLess = std::less<Key>,
         class Allocator = std::allocator<std::pair<const Key, T>>>
struct ordered_map : std::vector<std::pair<const Key, T>, Allocator>;
```

A minimal map-like container that preserves insertion order for use within `nlohmann::basic_json<ordered_map>`.

## Template parameters

`Key`
:   key type

`T`
:   mapped type

`IgnoredLess`
:   comparison function (ignored and only added to ensure compatibility with `std::map`)

`Allocator`
:   allocator type

## Member types

- **key_type** - key type (`Key`)
- **mapped_type** - mapped type (`T`)
- **Container** - base container type (`#!cpp std::vector<std::pair<const Key, T>, Allocator>`)
- **iterator**
- **const_iterator**
- **size_type**
- **value_type**

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

## Version history

- Added in version 3.9.0 to implement [`nlohmann::ordered_json`](ordered_json.md).
