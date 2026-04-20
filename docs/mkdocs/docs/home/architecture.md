# Architecture

!!! info

    This page is still under construction. Its goal is to provide a high-level overview of the library's architecture.
    This should help new contributors to get an idea of the used concepts and where to make changes.

## Overview

The main structure is class [nlohmann::basic_json](../api/basic_json/index.md).

It combines three roles in one type:

- the public JSON API (`parse`, `dump`, element access, conversion helpers, binary format support),
- the container-like interface for arrays and objects, and
- the iterator types that make JSON values integrate with generic STL-style code.

Most of the implementation details live in the `nlohmann::detail` namespace. `basic_json` ties these helpers together and
exposes the stable API surface used by the `json` and `ordered_json` aliases.

## Template specializations

`basic_json` is heavily parameterized so the same implementation can be reused with different object, array, string,
number, allocator, serializer, and binary container types.

- [`json`](../api/json.md) is the default alias used throughout the documentation.
- [`ordered_json`](../api/ordered_json.md) swaps the default object type for [`ordered_map`](../api/ordered_map.md) to
  preserve insertion order during object iteration and serialization.

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

Text and binary parsing start by normalizing the input through **input adapters**. These wrappers present different
source types behind a shared interface:

```cpp
/// read a single character
std::char_traits<char>::int_type get_character() noexcept;

/// read multiple characters to a destination buffer and
/// returns the number of characters successfully read
template<class T>
std::size_t get_elements(T* dest, std::size_t count = 1);
```

Common examples are `file_input_adapter` for `FILE*`, `input_stream_adapter` for `std::istream`,
`iterator_input_adapter` for iterator pairs, and the span/contiguous-byte adapters used for buffers in memory. Once an
adapter is created, `detail::parser` handles textual JSON and `detail::binary_reader` handles CBOR, MessagePack,
UBJSON, BSON, and BJData.

## SAX Interface

The parser is event-driven internally. The public SAX entry point is
[`basic_json::sax_parse`](../api/basic_json/sax_parse.md), which emits callbacks defined by
[`json_sax`](../api/json_sax/index.md) such as `null`, `key`, `start_object`, and `parse_error`.

The same interface is reused by internal consumers:

- `json_sax_dom_parser` builds a complete DOM,
- `json_sax_dom_callback_parser` applies the user callback used by `parse`, and
- `json_sax_acceptor` validates input for `accept` without materializing a JSON value.

The dedicated [SAX interface page](../features/parsing/sax_interface.md) contains the full callback list and a minimal
custom handler example.

## Writing outputs (serialization)

Serialization follows the same pattern in the other direction: serializers write to **output adapters** instead of
talking to strings, streams, or byte buffers directly.

```cpp
template<typename T>
void write_character(CharType c);

template<typename CharType>
void write_characters(const CharType* s, std::size_t length);
```

Examples include `output_string_adapter` for `std::string`, `output_stream_adapter` for `std::ostream`, and
`output_vector_adapter` for byte-oriented containers. These adapters are used by the text serializer as well as the
binary writers behind functions such as `to_cbor`, `to_msgpack`, and `to_bson`.

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
