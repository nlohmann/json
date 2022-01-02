# <small>nlohmann::json_sax::</small>start_object

```cpp
virtual bool start_object(std::size_t elements) = 0;
```

The beginning of an object was read.

## Parameters

`elements` (in)
:   number of object elements or `#!cpp -1` if unknown

## Return value

Whether parsing should proceed.

## Notes

Binary formats may report the number of elements.

## Version history

- Added in version 3.2.0.
