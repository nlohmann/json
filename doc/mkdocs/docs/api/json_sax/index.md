# <small>nlohmann::</small>json_sax

```cpp
template<typename BasicJsonType>
struct json_sax;
```

This class describes the SAX interface used by [sax_parse](../basic_json/sax_parse.md). Each function is called in
different situations while the input is parsed. The boolean return value informs the parser whether to continue
processing the input.

## Template parameters

`BasicJsonType`
:   a specialization of [`basic_json`](../basic_json/index.md)

## Member types

- [**number_integer_t**](../basic_json/number_integer_t.md) - `BasicJsonType`'s type for numbers (integer)
- [**number_unsigned_t**](../basic_json/number_unsigned_t.md) - `BasicJsonType`'s  type for numbers (unsigned)
- [**number_float_t**](../basic_json/number_float_t.md) - `BasicJsonType`'s type for numbers (floating-point)
- [**string_t**](../basic_json/string_t.md) - `BasicJsonType`'s type for strings
- [**binary_t**](../basic_json/binary_t.md) - `BasicJsonType`'s type for binary arrays

## Member functions

- [**binary**](binary.md) (_virtual_) - a binary value was read
- [**boolean**](boolean.md) (_virtual_) - a boolean value was read
- [**end_array**](end_array.md) (_virtual_) - the end of an array was read
- [**end_object**](end_object.md) (_virtual_) - the end of an object was read
- [**key**](key.md) (_virtual_) - an object key was read
- [**null**](null.md) (_virtual_) - a null value was read
- [**number_float**](number_float.md) (_virtual_) - a floating-point number was read
- [**number_integer**](number_integer.md) (_virtual_) - an integer number was read
- [**number_unsigned**](number_unsigned.md) (_virtual_) - an unsigned integer number was read
- [**parse_error**](parse_error.md) (_virtual_) - a parse error occurred
- [**start_array**](start_array.md) (_virtual_) - the beginning of an array was read
- [**start_object**](start_object.md) (_virtual_) - the beginning of an object was read
- [**string**](string.md) (_virtual_) - a string value was read

## Version history

- Added in version 3.2.0.
- Support for binary values (`binary_t`, `binary`) added in version 3.8.0.
