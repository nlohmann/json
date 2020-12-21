# basic_json::operator""_json

```cpp
json operator "" _json(const char* s, std::size_t n)
```

This operator implements a user-defined string literal for JSON objects. It can be used by adding `#!cpp _json` to a
string literal and returns a [`json`](../json.md) object if no parse error occurred.

## Parameters

`s` (in)
:   a string representation of a JSON object

`n` (in)
:   length of string `s`

## Return value

[`json`](../json.md) value parsed from `s`

## Exceptions

The function can throw anything that [`parse(s, s+n)`](parse.md) would throw.

## Complexity

Linear.

## Version history

- Added in version 1.0.0.
