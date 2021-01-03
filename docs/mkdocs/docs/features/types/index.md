# Types

This page gives an overview how JSON values are stored and how this can be configured.

## Overview

By default, JSON values are stored as follows:

| JSON type | C++ type                                      |
|-----------|-----------------------------------------------|
| object    | `std::map<std::string, basic_json>`           |
| array     | `std::vector<basic_json>`                     |
| null      | `std::nullptr_t`                              |
| string    | `std::string`                                 |
| boolean   | `bool`                                        |
| number    | `std::int64_t`, `std::uint64_t`, and `double` |

Note there are three different types for numbers - when parsing JSON text, the best fitting type is chosen.

## Storage

```plantuml
enum value_t {
    null
    object
    array
    string
    boolean
    number_integer
    number_unsigned
    number_float
    binary
    discarded
}

class json_value << (U,orchid) >> {
    object_t* object
    array_t* array
    string_t* string
    binary_t* binary
    boolean_t boolean
    number_integer_t number_integer
    number_unsigned_t number_unsigned
    number_float_t number_float
}

class basic_json {
    -- type and value --
    value_t m_type
    json_value m_value
    -- derived types --
    + <u>typedef</u> object_t
    + <u>typedef</u> array_t
    + <u>typedef</u> binary_t
    + <u>typedef</u> boolean_t
    + <u>typedef</u> number_integer_t
    + <u>typedef</u> number_unsigned_t
    + <u>typedef</u> number_float_t
}

basic_json .. json_value
basic_json .. value_t
```

## Template arguments

The data types to store a JSON value are derived from the template arguments passed to class `basic_json`:

```cpp
template<
    template<typename U, typename V, typename... Args> class ObjectType = std::map,
    template<typename U, typename... Args> class ArrayType = std::vector,
    class StringType = std::string,
    class BooleanType = bool,
    class NumberIntegerType = std::int64_t,
    class NumberUnsignedType = std::uint64_t,
    class NumberFloatType = double,
    template<typename U> class AllocatorType = std::allocator,
    template<typename T, typename SFINAE = void> class JSONSerializer = adl_serializer,
    class BinaryType = std::vector<std::uint8_t>
>
class basic_json;
```

Type `json` is an alias for `basic_json<>` and uses the default types.

From the template arguments, the following types are derived:

```cpp
using object_comparator_t = std::less<>;
using object_t = ObjectType<StringType, basic_json, object_comparator_t,
                   AllocatorType<std::pair<const StringType, basic_json>>>;

using array_t = ArrayType<basic_json, AllocatorType<basic_json>>;

using string_t = StringType;

using boolean_t = BooleanType;

using number_integer_t = NumberIntegerType;
using number_unsigned_t = NumberUnsignedType;
using number_float_t = NumberFloatType;

using binary_t = nlohmann::byte_container_with_subtype<BinaryType>;
```


## Objects

[RFC 8259](https://tools.ietf.org/html/rfc8259) describes JSON objects as follows:

> An object is an unordered collection of zero or more name/value pairs, where a name is a string and a value is a string, number, boolean, null, object, or array.

### Default type

With the default values for *ObjectType* (`std::map`), *StringType* (`std::string`), and *AllocatorType* (`std::allocator`), the default value for `object_t` is:

```cpp
std::map<
  std::string, // key_type
  basic_json, // value_type
  std::less<>, // key_compare
  std::allocator<std::pair<const std::string, basic_json>> // allocator_type
>
```

### Behavior

The choice of `object_t` influences the behavior of the JSON class. With the default type, objects have the following behavior:

- When all names are unique, objects will be interoperable in the sense that all software implementations receiving that object will agree on the name-value mappings.
- When the names within an object are not unique, it is unspecified which one of the values for a given key will be chosen. For instance, `#!json {"key": 2, "key": 1}` could be equal to either `#!json {"key": 1}` or `#!json {"key": 2}`.
- Internally, name/value pairs are stored in lexicographical order of the names. Objects will also be serialized (see `dump`) in this order. For instance, both `#!json {"b": 1, "a": 2}` and `#!json {"a": 2, "b": 1}` will be stored and serialized as `#!json {"a": 2, "b": 1}`.
- When comparing objects, the order of the name/value pairs is irrelevant. This makes objects interoperable in the sense that they will not be affected by these differences. For instance, `#!json {"b": 1, "a": 2}` and `#!json {"a": 2, "b": 1}` will be treated as equal.

### Key order

The order name/value pairs are added to the object is *not* preserved by the library. Therefore, iterating an object may return name/value pairs in a different order than they were originally stored. In fact, keys will be traversed in alphabetical order as `std::map` with `std::less` is used by default. Please note this behavior conforms to [RFC 8259](https://tools.ietf.org/html/rfc8259), because any order implements the specified "unordered" nature of JSON objects.

### Limits

[RFC 8259](https://tools.ietf.org/html/rfc8259) specifies:

> An implementation may set limits on the maximum depth of nesting.

In this class, the object's limit of nesting is not explicitly constrained. However, a maximum depth of nesting may be introduced by the compiler or runtime environment. A theoretical limit can be queried by calling the `max_size` function of a JSON object.

### Storage

Objects are stored as pointers in a `basic_json` type. That is, for any access to object values, a pointer of type `object_t*` must be dereferenced.


## Arrays

[RFC 8259](https://tools.ietf.org/html/rfc8259) describes JSON arrays as follows:

> An array is an ordered sequence of zero or more values.

### Default type

With the default values for *ArrayType* (`std::vector`) and *AllocatorType* (`std::allocator`), the default value for `array_t` is:

```cpp
std::vector<
  basic_json, // value_type
  std::allocator<basic_json> // allocator_type
>
```

### Limits

[RFC 8259](https://tools.ietf.org/html/rfc8259) specifies:

> An implementation may set limits on the maximum depth of nesting.

In this class, the array's limit of nesting is not explicitly constrained. However, a maximum depth of nesting may be introduced by the compiler or runtime environment. A theoretical limit can be queried by calling the `max_size` function of a JSON array.

### Storage

Arrays are stored as pointers in a `basic_json` type. That is, for any access to array values, a pointer of type `array_t*` must be dereferenced.


## Strings

[RFC 8259](https://tools.ietf.org/html/rfc8259) describes JSON strings as follows:

> A string is a sequence of zero or more Unicode characters.

Unicode values are split by the JSON class into byte-sized characters during deserialization.

### Default type

With the default values for *StringType* (`std::string`), the default value for `string_t` is `#!cpp std::string`.

### Encoding

Strings are stored in UTF-8 encoding. Therefore, functions like `std::string::size()` or `std::string::length()` return the number of **bytes** in the string rather than the number of characters or glyphs.

### String comparison

[RFC 8259](https://tools.ietf.org/html/rfc8259) states:

> Software implementations are typically required to test names of object members for equality. Implementations that transform the textual representation into sequences of Unicode code units and then perform the comparison numerically, code unit by code unit, are interoperable in the sense that implementations will agree in all cases on equality or inequality of two strings. For example, implementations that compare strings with escaped characters unconverted may incorrectly find that `"a\\b"` and `"a\u005Cb"` are not equal.

This implementation is interoperable as it does compare strings code unit by code unit.

### Storage

String values are stored as pointers in a `basic_json` type. That is, for any access to string values, a pointer of type `string_t*` must be dereferenced.


## Booleans

[RFC 8259](https://tools.ietf.org/html/rfc8259) implicitly describes a boolean as a type which differentiates the two literals `true` and `false`.

### Default type

With the default values for *BooleanType* (`#!cpp bool`), the default value for `boolean_t` is `#!cpp bool`.

### Storage

Boolean values are stored directly inside a `basic_json` type.

## Numbers

See the [number handling](number_handling.md) article for a detailed discussion on how numbers are handled by this library.

[RFC 8259](https://tools.ietf.org/html/rfc8259) describes numbers as follows:

> The representation of numbers is similar to that used in most programming languages. A number is represented in base 10 using decimal digits. It contains an integer component that may be prefixed with an optional minus sign, which may be followed by a fraction part and/or an exponent part. Leading zeros are not allowed. (...) Numeric values that cannot be represented in the grammar below (such as Infinity and NaN) are not permitted.

This description includes both integer and floating-point numbers. However, C++ allows more precise storage if it is known whether the number is a signed integer, an unsigned integer or a floating-point number. Therefore, three different types, `number_integer_t`, `number_unsigned_t`, and `number_float_t` are used.

### Default types

With the default values for *NumberIntegerType* (`std::int64_t`), the default value for `number_integer_t` is `std::int64_t`.
With the default values for *NumberUnsignedType* (`std::uint64_t`), the default value for `number_unsigned_t` is `std::uint64_t`.
With the default values for *NumberFloatType* (`#!cpp double`), the default value for `number_float_t` is `#!cpp double`.

### Default behavior

- The restrictions about leading zeros is not enforced in C++. Instead, leading zeros in integer literals lead to an interpretation as octal number. Internally, the value will be stored as decimal number. For instance, the C++ integer literal `#!c 010` will be serialized to `#!c 8`. During deserialization, leading zeros yield an error.
- Not-a-number (NaN) values will be serialized to `#!json null`.

### Limits

[RFC 8259](https://tools.ietf.org/html/rfc8259) specifies:

> An implementation may set limits on the range and precision of numbers.

When the default type is used, the maximal integer number that can be stored is `#!c 9223372036854775807` (`INT64_MAX`) and the minimal integer number that can be stored is `#!c -9223372036854775808` (`INT64_MIN`). Integer numbers that are out of range will yield over/underflow when used in a constructor. During deserialization, too large or small integer numbers will be automatically be stored as `number_unsigned_t` or `number_float_t`.

When the default type is used, the maximal unsigned integer number that can be stored is `#!c 18446744073709551615` (`UINT64_MAX`) and the minimal integer number that can be stored is `#!c 0`. Integer numbers that are out of range will yield over/underflow when used in a constructor. During deserialization, too large or small integer numbers will be automatically be stored as `number_integer_t` or `number_float_t`.

[RFC 8259](https://tools.ietf.org/html/rfc8259) further states:

> Note that when such software is used, numbers that are integers and are in the range $[-2^{53}+1, 2^{53}-1]$ are interoperable in the sense that implementations will agree exactly on their numeric values.

As this range is a subrange of the exactly supported range [`INT64_MIN`, `INT64_MAX`], this class's integer type is interoperable.

[RFC 8259](https://tools.ietf.org/html/rfc8259) states:

> This specification allows implementations to set limits on the range and precision of numbers accepted. Since software that implements IEEE 754-2008 binary64 (double precision) numbers is generally available and widely used, good interoperability can be achieved by implementations that expect no more precision or range than these provide, in the sense that implementations will approximate JSON numbers within the expected precision.

This implementation does exactly follow this approach, as it uses double precision floating-point numbers. Note values smaller than `#!c -1.79769313486232e+308` and values greater than `#!c 1.79769313486232e+308` will be stored as NaN internally and be serialized to `#!json null`.

### Storage

Integer number values, unsigned integer number values, and floating-point number values are stored directly inside a `basic_json` type.
