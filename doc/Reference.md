# Reference

## Nomenclature

We use the term "JSON" when we mean the [JavaScript Object Notation](http://json.org); that is, the file format. When we talk about the class implementing our library, we use "`json`" (typewriter font). Instances of this class are called "`json` values" to differentiate them from "JSON objects"; that is, unordered mappings, hashes, and whatnot.

## Types and default values

This table describes how JSON values are mapped to C++ types.

| JSON type               | value_type                 | C++ type                      | type alias             | default value |
| ----------------------- | -------------------------- | ----------------------------- | ---------------------- | --------------
| null                    | `value_type::null`         | `nullptr_t`                   | -                      | `nullptr`     |
| string                  | `value_type::string`       | `std::string`                 | `json::string_t`       | `""`          |
| number (integer)        | `value_type::number`       | `int`                         | `json::number_t`       | `0`           |
| number (floating point) | `value_type::number_float` | `double`                      | `json::number_float_t` | `0.0`         |
| array                   | `value_type::array `       | `std::array<json>`            | `json::array_t`        | `{}`          |
| object                  | `value_type::object`       | `std::map<std::string, json>` | `json::object_t`       | `{}`          |

The second column list entries of an enumeration `value_type` which can be queried by calling `type()` on a `json` value. The column "C++ types" list the internal type that is used to represent the respective JSON value. The "type alias" column furthermore lists type aliases that are used in the `json` class to allow for more flexibility. The last column list the default value; that is, the value that is set if none is passed to the constructor or that is set if `clear()` is called.

## Type conversions

There are only a few type conversions possible:

- An integer number can be translated to a floating point number.
- A floating point number can be translated to an integer number. Note the number is truncated and not rounded, ceiled or floored.
- Any value (i.e., boolean, string, number, null) but JSON objects can be translated into an array. The result is a singleton array that consists of the value before.
- Any other conversion will throw a `std::logic_error` exception.

When compatible, `json` values **implicitly convert** to `std::string`, `int`, `double`, `json::array_t`, and `json::object_t`. Furthermore, **explicit type conversion** is possible using the `get<>()` function with the aforementioned types.

## Initialization

`json` values can be created from many literals and variable types:

| JSON type | literal/variable types | examples |
| --------- | ---------------------- | -------- |
| none      | null pointer literal, `nullptr_t` type, no value | `nullptr` |
| boolean   | boolean literals, `bool` type, `json::boolean_t` type | `true`, `false` |
| string    | string literal, `char*` type, `std::string` type, `std::string&&` rvalue reference, `json::string_t` type | `"Hello"` |
| number (integer) | integer literal, `short int` type, `int` type, `json_number_t` type | `42` |
| number (floating point) | floating point literal, `float` type, `double` type, `json::number_float_t` type | `3.141529`
| array | initializer list whose elements are `json` values (or can be translated into `json` values using the rules above), `std::vector<json>` type, `json::array_t` type, `json::array_t&&` rvalue reference | `{1, 2, 3, true, "foo"}` |
| object | initializer list whose elements are pairs of a string literal and a `json` value (or can be translated into `json` values using the rules above), `std::map<std::string, json>` type, `json::object_t` type, `json::object_t&&` rvalue reference | `{ {"key1", 42}, {"key2", false} }` |

## Number types

[![JSON number format](http://json.org/number.gif)](http://json.org)

The JSON specification explicitly does not define an internal number representation, but only the syntax of how numbers can be written down. Consequently, we would need to use the largest possible floating point number format (e.g., `long double`) to internally store JSON numbers.

However, this would be a waste of space, so we let the JSON parser decide which format to use: If the number can be precisely stored in an `int`, we use an `int` to store it. However, if it is a floating point number, we use `double` to store it.
