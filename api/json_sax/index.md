# nlohmann::json_sax

```
template<typename BasicJsonType>
struct json_sax;
```

This class describes the SAX interface used by [sax_parse](https://json.nlohmann.me/api/basic_json/sax_parse/index.md). Each function is called in different situations while the input is parsed. The boolean return value informs the parser whether to continue processing the input.

## Template parameters

`BasicJsonType` : a specialization of [`basic_json`](https://json.nlohmann.me/api/basic_json/index.md)

## Member types

- [**number_integer_t**](https://json.nlohmann.me/api/basic_json/number_integer_t/index.md) - `BasicJsonType`'s type for numbers (integer)
- [**number_unsigned_t**](https://json.nlohmann.me/api/basic_json/number_unsigned_t/index.md) - `BasicJsonType`'s type for numbers (unsigned)
- [**number_float_t**](https://json.nlohmann.me/api/basic_json/number_float_t/index.md) - `BasicJsonType`'s type for numbers (floating-point)
- [**string_t**](https://json.nlohmann.me/api/basic_json/string_t/index.md) - `BasicJsonType`'s type for strings
- [**binary_t**](https://json.nlohmann.me/api/basic_json/binary_t/index.md) - `BasicJsonType`'s type for binary arrays

## Member functions

- [**binary**](https://json.nlohmann.me/api/json_sax/binary/index.md) (*virtual*) - a binary value was read
- [**boolean**](https://json.nlohmann.me/api/json_sax/boolean/index.md) (*virtual*) - a boolean value was read
- [**end_array**](https://json.nlohmann.me/api/json_sax/end_array/index.md) (*virtual*) - the end of an array was read
- [**end_object**](https://json.nlohmann.me/api/json_sax/end_object/index.md) (*virtual*) - the end of an object was read
- [**key**](https://json.nlohmann.me/api/json_sax/key/index.md) (*virtual*) - an object key was read
- [**null**](https://json.nlohmann.me/api/json_sax/null/index.md) (*virtual*) - a null value was read
- [**number_float**](https://json.nlohmann.me/api/json_sax/number_float/index.md) (*virtual*) - a floating-point number was read
- [**number_integer**](https://json.nlohmann.me/api/json_sax/number_integer/index.md) (*virtual*) - an integer number was read
- [**number_unsigned**](https://json.nlohmann.me/api/json_sax/number_unsigned/index.md) (*virtual*) - an unsigned integer number was read
- [**parse_error**](https://json.nlohmann.me/api/json_sax/parse_error/index.md) (*virtual*) - a parse error occurred
- [**start_array**](https://json.nlohmann.me/api/json_sax/start_array/index.md) (*virtual*) - the beginning of an array was read
- [**start_object**](https://json.nlohmann.me/api/json_sax/start_object/index.md) (*virtual*) - the beginning of an object was read
- [**string**](https://json.nlohmann.me/api/json_sax/string/index.md) (*virtual*) - a string value was read

## Version history

- Added in version 3.2.0.
- Support for binary values (`binary_t`, `binary`) added in version 3.8.0.
