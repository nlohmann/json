# Reference

## Types and default values

| JSON type               | value_type                 | C++ type                      | type alias             | default value |
| ----------------------- | -------------------------- | ----------------------------- | ---------------------- | --------------
| null                    | `value_type::null`         | `nullptr_t`                   | -                      | `nullptr`     |
| string                  | `value_type::string`       | `std::string`                 | `JSON::string_t`       | `""`          |
| number (integer)        | `value_type::number`       | `int`                         | `JSON::number_t`       | `0`           |
| number (floating point) | `value_type::number_float` | `double`                      | `JSON::number_float_t` | `0.0`         |
| array                   | `value_type::array `       | `std::array<JSON>`            | `JSON::array_t`        | `{}`          |
| object                  | `value_type::object`       | `std::map<std::string, JSON>` | `JSON::object_t`       | `{}`          |

## Conversions

There are only a few type conversions possible:

- An integer number can be translated to a floating point number (e.g., by calling `get<double>()`).
- A floating pointnnumber can be translated to an integer number (e.g., by calling `get<int>()`). Note the number is truncated and not rounded, ceiled or floored.
- Any value but JSON objects can be translated into an array. The result is a singleton array that consists of the value before.
- Any other conversion will throw a `std::logic_error` exception.

## Initialization

JSON values can be created from many literals and variable types:

| JSON type | literal/variable types | examples |
| --------- | ---------------------- | -------- |
| none      | null pointer literal, `nullptr_t` type, no value | `nullptr` |
| boolean   | boolean literals, `bool` type, `JSON::boolean_t` type | `true`, `false` |
| string    | string literal, `char*` type, `std::string` type, `std::string&&` rvalue reference, `JSON::string_t` type | `"Hello"` |
| number (integer) | integer literal, `short int` type, `int` type, `JSON_number_t` type | `42` |
| number (floating point) | floating point literal, `float` type, `double` type, `JSON::number_float_t` type | `3.141529`
| array | initializer list whose elements are `JSON` values (or can be translated into `JSON` values using the rules above), `std::vector<JSON>` type, `JSON::array_t` type | `{1, 2, 3, true, "foo"}` |
| object | initializer list whose elements are pairs of a string literal and a `JSON` value (or can be translated into `JSON` values using the rules above), `std::map<std::string, JSON>` type, `JSON::object_t` type | { {"key1", 42}, {"key2", false} } |
