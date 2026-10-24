# <small>nlohmann::json_sax::</small>json_sax

```cpp
// (1)
json_sax() = default;

// (2)
json_sax(const json_sax&) = default;

// (3)
json_sax(json_sax&&) noexcept = default;
```

1. Default constructor.
2. Copy constructor.
3. Move constructor.

`json_sax` is a pure abstract base class with no data members of its own, so all three constructors are
defaulted and only exist to make derived SAX consumers explicitly copyable/movable.

## Exception safety

No-throw guarantee: none of these constructors throw exceptions.

## Complexity

Constant.

<!-- NOLINT Examples -->

## Version history

- Added in version 3.2.0.
