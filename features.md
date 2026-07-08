# Features

This section describes the features of the library in detail. If you are new to the library, the pages below are
roughly ordered along a typical workflow: create or parse a value, access and modify it, convert it to and from your own
C++ types, and finally serialize it again.

## Creating and reading values

- [Creating JSON values](creating_values.md) — build values from literals, initializer lists, and STL containers, and
  understand the `#!cpp {}` vs. `#!cpp []` ambiguity.
- [Parsing](parsing/index.md) — read a JSON value from a string, file, or stream, including
  [JSON Lines](parsing/json_lines.md), [callbacks](parsing/parser_callbacks.md), the
  [SAX interface](parsing/sax_interface.md), and [error handling](parsing/parse_exceptions.md).
- [Comments](comments.md) and [trailing commas](trailing_commas.md) — opt-in relaxations of the JSON grammar.

## Accessing and modifying values

- [Element access](element_access/index.md) — unchecked ([`operator[]`](element_access/unchecked_access.md)),
  checked ([`at`](element_access/checked_access.md)), and access with a
  [default value](element_access/default_value.md).
- [JSON Pointer](json_pointer.md) — address values deep inside a document with [RFC 6901](https://tools.ietf.org/html/rfc6901) pointers.
- [Iterators](iterators.md) — traverse arrays and objects.
- [Modifying values](modifying_values.md) — add, update, merge, and remove elements.
- [JSON Patch and Diff](json_patch.md) and [JSON Merge Patch](merge_patch.md) — apply and compute structured changes.

## Converting to and from C++ types

- [Converting values](conversions.md) — get values out with [`get`](../api/basic_json/get.md)/[`get_to`](../api/basic_json/get_to.md),
  and understand implicit conversions.
- [Arbitrary types conversions](arbitrary_types.md) — teach the library about your own structs and classes.
- [Specializing enum conversion](enum_conversion.md) — map enums to strings instead of integers.

## Serializing values

- [Serialization](serialization.md) — turn a value back into JSON text with [`dump`](../api/basic_json/dump.md),
  including pretty-printing and handling of non-ASCII and invalid UTF-8.
- [Binary formats](binary_formats/index.md) — encode values more compactly as
  [BJData](binary_formats/bjdata.md), [BSON](binary_formats/bson.md), [CBOR](binary_formats/cbor.md),
  [MessagePack](binary_formats/messagepack.md), or [UBJSON](binary_formats/ubjson.md).
- [Binary values](binary_values.md) — store and exchange raw byte sequences.

## How values are stored and configured

- [Types](types/index.md) and [number handling](types/number_handling.md) — how JSON types map to C++ types and how
  numbers are treated.
- [Object order](object_order.md) — keep insertion order with [`ordered_json`](../api/ordered_json.md).
- [Runtime assertions](assertions.md), [supported macros](macros.md), the [`nlohmann` namespace](namespace.md), and
  [C++ modules](modules.md) — build-time and runtime configuration.

!!! tip "Looking for a specific function?"

    This section gives conceptual overviews. For the precise signature, parameters, and return value of a function, see
    the [API Documentation](../api/basic_json/index.md).
