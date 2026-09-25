# <small>nlohmann::json_sax::</small>~json_sax

```cpp
virtual ~json_sax() = default;
```

Destructor. Virtual to allow proper destruction of derived SAX consumer classes through a
pointer/reference to `json_sax`.

## Exception safety

No-throw guarantee: this destructor never throws exceptions.

## Complexity

Constant.

<!-- NOLINT Examples -->

## Version history

- Added in version 3.2.0.
