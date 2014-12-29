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
