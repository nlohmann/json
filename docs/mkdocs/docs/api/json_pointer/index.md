# <small>nlohmann::</small>json_pointer

```cpp
template<typename RefStringType>
class json_pointer;
```

A JSON pointer defines a string syntax for identifying a specific value within a JSON document. It can be used with
functions [`at`](../basic_json/at.md) and [`operator[]`](../basic_json/operator%5B%5D.md). Furthermore, JSON pointers
are the base for JSON patches.

## Template parameters

`RefStringType`
:   the string type used for the reference tokens making up the JSON pointer

!!! warning "Deprecation"

    For backwards compatibility `RefStringType` may also be a specialization of [`basic_json`](../basic_json/index.md)
    in which case `string_t` will be deduced as [`basic_json::string_t`](../basic_json/string_t.md). This feature is
    deprecated and may be removed in a future major version.

## Member types

- [**string_t**](string_t.md) - the string type used for the reference tokens

## Member functions

- [(constructor)](json_pointer.md)
- [**to_string**](to_string.md) - return a string representation of the JSON pointer
- [**operator string_t**](operator_string.md) - return a string representation of the JSON pointer
- [**operator/=**](operator_slasheq.md) - append to the end of the JSON pointer
- [**operator/**](operator_slash.md) - create JSON Pointer by appending
- [**parent_pointer**](parent_pointer.md) - returns the parent of this JSON pointer
- [**pop_back**](pop_back.md) - remove last reference token
- [**back**](back.md) - return last reference token
- [**push_back**](push_back.md) - append an unescaped token at the end of the pointer
- [**empty**](empty.md) - return whether pointer points to the root document

## See also

- [operator""_json_pointer](../basic_json/operator_literal_json_pointer.md) - user-defined string literal for JSON pointers
- [RFC 6901](https://datatracker.ietf.org/doc/html/rfc6901)

## Version history

- Added in version 2.0.0.
- Changed template parameter from `basic_json` to string type in version 3.11.0.
