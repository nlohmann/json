# basic_json::string_t

```cpp
using string_t = StringType;
```

The type used to store JSON strings.

[RFC 8259](https://tools.ietf.org/html/rfc8259) describes JSON strings as follows:
> A string is a sequence of zero or more Unicode characters.

To store objects in C++, a type is defined by the template parameter described below. Unicode values are split by the
JSON class into byte-sized characters during deserialization.

## Template parameters

`StringType`
:   the container to store strings (e.g., `std::string`). Note this container is used for keys/names in objects, see
    [object_t](object_t.md).

## Notes

#### Default type

With the default values for `StringType` (`std::string`), the default value for `string_t` is `#!cpp std::string`.

#### Encoding

Strings are stored in UTF-8 encoding. Therefore, functions like `std::string::size()` or `std::string::length()` return
the number of bytes in the string rather than the number of characters or glyphs.

#### String comparison

[RFC 8259](https://tools.ietf.org/html/rfc8259) states:
> Software implementations are typically required to test names of object members for equality. Implementations that
> transform the textual representation into sequences of Unicode code units and then perform the comparison numerically,
> code unit by code unit, are interoperable in the sense that implementations will agree in all cases on equality or
> inequality of two strings. For example, implementations that compare strings with escaped characters unconverted may
> incorrectly find that `"a\\b"` and `"a\u005Cb"` are not equal.

This implementation is interoperable as it does compare strings code unit by code unit.

#### Storage

String values are stored as pointers in a `basic_json` type. That is, for any access to string values, a pointer of type
`string_t*` must be dereferenced.

## Version history

- Added in version 1.0.0.
