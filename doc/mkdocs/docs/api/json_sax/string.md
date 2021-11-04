# json_sax::string

```cpp
virtual bool string(string_t& val) = 0;
```

A string value was read.

## Parameters

`val` (in)
:   string value

## Return value

Whether parsing should proceed.

## Note

It is safe to move the passed string value.

## Version history

- Added in version 3.2.0.
