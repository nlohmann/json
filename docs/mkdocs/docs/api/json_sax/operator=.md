# <small>nlohmann::json_sax::</small>operator=

```cpp
// (1)
json_sax& operator=(const json_sax&) = default;

// (2)
json_sax& operator=(json_sax&&) noexcept = default;
```

1. Copy assignment operator.
2. Move assignment operator.

`json_sax` is a pure abstract base class with no data members of its own, so both assignment operators
are defaulted and only exist to make derived SAX consumers explicitly copy-/move-assignable.

## Exception safety

No-throw guarantee: neither operator throws exceptions.

## Complexity

Constant.

<!-- NOLINT Examples -->

## Version history

- Added in version 3.2.0.
