# <small>nlohmann::ordered_map::</small>ordered_map

```cpp
// (1)
ordered_map() noexcept(noexcept(Container()));

// (2)
explicit ordered_map(const Allocator& alloc) noexcept(noexcept(Container(alloc)));

// (3)
template <class It>
ordered_map(It first, It last, const Allocator& alloc = Allocator());

// (4)
ordered_map(std::initializer_list<value_type> init, const Allocator& alloc = Allocator());

// (5)
ordered_map(const ordered_map&) = default;

// (6)
ordered_map(ordered_map&&) noexcept(std::is_nothrow_move_constructible<Container>::value) = default;
```

1. Default constructor. Creates an empty `ordered_map`.
2. Creates an empty `ordered_map` using the given allocator.
3. Creates an `ordered_map` from the elements in range `[first, last)`, inserted in iteration order.
4. Creates an `ordered_map` from an initializer list of key/value pairs, inserted in list order.
5. Copy constructor.
6. Move constructor.

These constructors are declared explicitly (rather than inherited via `#!cpp using Container::Container`)
because older compilers (GCC <= 5.5, Xcode <= 9.4) do not handle the inherited constructors correctly.

## Template parameters

`It`
:   an input iterator type

## Parameters

`alloc` (in)
:   allocator to use for the underlying container

`first` (in)
:   iterator to the first element to insert

`last` (in)
:   iterator one past the last element to insert

`init` (in)
:   initializer list of key/value pairs to insert

## Complexity

1. Constant.
2. Constant.
3. Linear in the distance between `first` and `last`.
4. Linear in the size of `init`.
5. Linear in the size of `other`.
6. Constant.

<!-- NOLINT Examples -->

## Version history

- Added in version 3.9.0 to implement [`nlohmann::ordered_json`](../ordered_json.md).
