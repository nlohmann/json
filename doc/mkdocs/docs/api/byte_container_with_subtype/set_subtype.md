# byte_container_with_subtype::set_subtype

```cpp
void set_subtype(subtype_type subtype) noexcept
```

Sets the binary subtype of the value, also flags a binary JSON value as having a subtype, which has implications for
serialization.

## Parameters

`subtype` (in)
:   subtype to set

## Complexity

Constant.

## Exception safety

No-throw guarantee: this function never throws exceptions.

## Version history

Since version 3.8.0.
