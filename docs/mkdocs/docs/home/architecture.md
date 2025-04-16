# Architecture

!!! info

    This page is still under construction. Its goal is to provide a high-level overview of the library's architecture.
    This should help new contributors to get an idea of the used concepts and where to make changes.

## Overview

The main structure is class [nlohmann::basic_json](../api/basic_json/index.md).

- public API
- container interface
- iterators

## Template specializations

- describe template parameters of `basic_json`
- [`json`](../api/json.md)
- [`ordered_json`](../api/ordered_json.md) via [`ordered_map`](../api/ordered_map.md)

## Value storage

Values are stored as a tagged union of [value_t](../api/basic_json/value_t.md) and json_value.

```cpp
/// the type of the current element
value_t m_type = value_t::null;

/// the value of the current element
json_value m_value = {};
```

with

```cpp
enum class value_t : std::uint8_t
{
    null,             ///< null value
    object,           ///< object (unordered set of name/value pairs)
    array,            ///< array (ordered collection of values)
    string,           ///< string value
    boolean,          ///< boolean value
    number_integer,   ///< number value (signed integer)
    number_unsigned,  ///< number value (unsigned integer)
    number_float,     ///< number value (floating-point)
    binary,           ///< binary array (ordered collection of bytes)
    discarded         ///< discarded by the parser callback function
};

union json_value {
  /// object (stored with pointer to save storage)
  object_t *object;
  /// array (stored with pointer to save storage)
  array_t *array;
  /// string (stored with pointer to save storage)
  string_t *string;
  /// binary (stored with pointer to save storage)
  binary_t *binary;
  /// boolean
  boolean_t boolean;
  /// number (integer)
  number_integer_t number_integer;
  /// number (unsigned integer)
  number_unsigned_t number_unsigned;
  /// number (floating-point)
  number_float_t number_float;
};
```

## Parsing inputs (deserialization)

Input is read via **input adapters** that abstract a source with a common interface:

```cpp
/// read a single character
std::char_traits<char>::int_type get_character() noexcept;

/// read multiple characters to a destination buffer and
/// returns the number of characters successfully read
template<class T>
std::size_t get_elements(T* dest, std::size_t count = 1);
```

List examples of input adapters.

## SAX Interface

TODO

## Writing outputs (serialization)

Output is written via **output adapters**:

```cpp
template<typename T>
void write_character(CharType c);

template<typename CharType>
void write_characters(const CharType* s, std::size_t length);
```

List examples of output adapters.

## Value conversion

```cpp
template<class T>
void to_json(basic_json& j, const T& t);

template<class T>
void from_json(const basic_json& j, T& t);
```

## Additional features

- JSON Pointers
- Binary formats
- Custom base class
- Conversion macros

## Details namespace

- C++ feature backports
