# <small>nlohmann::json_sax::</small>binary

```cpp
virtual bool binary(binary_t& val) = 0;
```

A binary value was read.

## Parameters

`val` (in)
:   binary value

## Return value

Whether parsing should proceed.

## Notes

It is safe to move the passed binary value.

## Version history

- Added in version 3.8.0.
