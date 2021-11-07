# <small>nlohmann::byte_container_with_subtype::</small>set_subtype

```cpp
void set_subtype(subtype_type subtype) noexcept;
```

Sets the binary subtype of the value, also flags a binary JSON value as having a subtype, which has implications for
serialization.

## Parameters

`subtype` (in)
:   subtype to set

## Exception safety

No-throw guarantee: this function never throws exceptions.

## Complexity

Constant.

## Version history

Since version 3.8.0.
