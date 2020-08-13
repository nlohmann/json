# basic_json::operator""_json_pointer

```cpp
json_pointer operator "" _json_pointer(const char* s, std::size_t n)
```

This operator implements a user-defined string literal for JSON Pointers. It can be used by adding `#!cpp _json_pointer`
to a string literal and returns a [`json_pointer`](../json_pointer.md) object if no parse error occurred.

## Parameters

`s` (in)
:   a string representation of a JSON Pointer

`n` (in)
:   length of string `s`

## Return value

[`json_pointer`](../json_pointer.md) value parsed from `s`

## Exceptions

The function can throw anything that [`json_pointer::json_pointer`](../json_pointer.md) would throw.

## Complexity

Linear.

## Version history

- Added in version 2.0.0.
