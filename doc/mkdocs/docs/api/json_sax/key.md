# <small>nlohmann::json_sax::</small>key

```cpp
virtual bool key(string_t& val) = 0;
```

An object key was read.

## Parameters

`val` (in)
:   object key

## Return value

Whether parsing should proceed.

## Notes

It is safe to move the passed object key value.

## Version history

- Added in version 3.2.0.
