# basic_json::get_binary

```cpp
binary_t& get_binary();

const binary_t& get_binary() const;
```

Returns a reference to the stored binary value.

## Return value

Reference to binary value.

## Exception safety

Strong exception safety: if an exception occurs, the original value stays intact.

## Exceptions

Throws [`type_error.302`](../../home/exceptions.md#jsonexceptiontype_error302) if the value is not binary

## Complexity

Constant.

## Version history

- Added in version 3.8.0.
