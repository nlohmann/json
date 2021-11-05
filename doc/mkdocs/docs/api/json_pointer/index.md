# json_pointer

```cpp
template<typename BasicJsonType>
class json_pointer;
```

JSON Pointer defines a string syntax for identifying a specific value within a JSON document.

## Template parameters

`BasicJsonType`
:   a specialization of [`basic_json`](../basic_json/index.md)

## Member functions

- [(constructor)](json_pointer.md)
- [**to_string**](to_string.md) - return a string representation of the JSON pointer
- [**operator std::string**](operator_string.md) - return a string representation of the JSON pointer
- [**operator/=**](operator_slasheq.md) - append to the end of the JSON pointer
- [**operator/**](operator_slash.md) - create JSON Pointer by appending
- [**parent_pointer**](parent_pointer.md) - returns the parent of this JSON pointer
- [**pop_back**](pop_back.md) - remove last reference token
- [**back**](back.md) - return last reference token
- [**push_back**](push_back.md) - append an unescaped token at the end of the pointer
- [**empty**](empty.md) - return whether pointer points to the root document

## See also

[RFC 6901](https://datatracker.ietf.org/doc/html/rfc6901)

## Version history

Added in version 2.0.0.
