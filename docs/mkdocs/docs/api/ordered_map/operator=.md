# <small>nlohmann::ordered_map::</small>operator=

```cpp
// (1)
ordered_map& operator=(const ordered_map& other);

// (2)
ordered_map& operator=(ordered_map&& other) noexcept(std::is_nothrow_move_assignable<Container>::value);
```

1. Copy assignment operator.
2. Move assignment operator.

## Parameters

`other` (in)
:   value to assign from

## Return value

`*this`

## Complexity

1. Linear in the size of `other`.
2. Constant.

<!-- NOLINT Examples -->

## Version history

- Added in version 3.9.0 to implement [`nlohmann::ordered_json`](../ordered_json.md).
