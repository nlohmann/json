# nlohmann::json_pointer

```
template<typename RefStringType>
class json_pointer;
```

A JSON pointer defines a string syntax for identifying a specific value within a JSON document. It can be used with functions [`at`](https://json.nlohmann.me/api/basic_json/at/index.md) and [`operator[]`](https://json.nlohmann.me/api/basic_json/operator%5B%5D/index.md). Furthermore, JSON pointers are the base for JSON patches.

## Template parameters

`RefStringType` : the string type used for the reference tokens making up the JSON pointer

Deprecation

For backwards compatibility `RefStringType` may also be a specialization of [`basic_json`](https://json.nlohmann.me/api/basic_json/index.md) in which case `string_t` will be deduced as [`basic_json::string_t`](https://json.nlohmann.me/api/basic_json/string_t/index.md). This feature is deprecated and may be removed in a future major version.

## Member types

- [**string_t**](https://json.nlohmann.me/api/json_pointer/string_t/index.md) - the string type used for the reference tokens

## Member functions

- [(constructor)](https://json.nlohmann.me/api/json_pointer/json_pointer/index.md)
- [**to_string**](https://json.nlohmann.me/api/json_pointer/to_string/index.md) - return a string representation of the JSON pointer
- [**operator string_t**](https://json.nlohmann.me/api/json_pointer/operator_string_t/index.md) - return a string representation of the JSON pointer
- [**operator==**](https://json.nlohmann.me/api/json_pointer/operator_eq/index.md) - compare: equal
- [**operator!=**](https://json.nlohmann.me/api/json_pointer/operator_ne/index.md) - compare: not equal
- [**operator/=**](https://json.nlohmann.me/api/json_pointer/operator_slasheq/index.md) - append to the end of the JSON pointer
- [**operator/**](https://json.nlohmann.me/api/json_pointer/operator_slash/index.md) - create JSON Pointer by appending
- [**parent_pointer**](https://json.nlohmann.me/api/json_pointer/parent_pointer/index.md) - returns the parent of this JSON pointer
- [**pop_back**](https://json.nlohmann.me/api/json_pointer/pop_back/index.md) - remove the last reference token
- [**back**](https://json.nlohmann.me/api/json_pointer/back/index.md) - return last reference token
- [**push_back**](https://json.nlohmann.me/api/json_pointer/push_back/index.md) - append an unescaped token at the end of the pointer
- [**pop_front**](https://json.nlohmann.me/api/json_pointer/pop_front/index.md) - remove the first reference token
- [**front**](https://json.nlohmann.me/api/json_pointer/front/index.md) - return first reference token
- [**push_front**](https://json.nlohmann.me/api/json_pointer/push_front/index.md) - append an unescaped token at the start of the pointer
- [**empty**](https://json.nlohmann.me/api/json_pointer/empty/index.md) - return whether the pointer points to the root document

## Literals

- [**operator""\_json_pointer**](https://json.nlohmann.me/api/operator_literal_json_pointer/index.md) - user-defined string literal for JSON pointers

## See also

- [RFC 6901](https://datatracker.ietf.org/doc/html/rfc6901)

## Version history

- Added in version 2.0.0.
- Changed template parameter from `basic_json` to string type in version 3.11.0.
