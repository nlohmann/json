# Features

This section describes the features of the library in detail. If you are new to the library, the pages below are roughly ordered along a typical workflow: create or parse a value, access and modify it, convert it to and from your own C++ types, and finally serialize it again.

## Creating and reading values

- [Creating JSON values](https://json.nlohmann.me/features/creating_values/index.md) — build values from literals, initializer lists, and STL containers, and understand the `{}` vs. `[]` ambiguity.
- [Parsing](https://json.nlohmann.me/features/parsing/index.md) — read a JSON value from a string, file, or stream, including [JSON Lines](https://json.nlohmann.me/features/parsing/json_lines/index.md), [callbacks](https://json.nlohmann.me/features/parsing/parser_callbacks/index.md), the [SAX interface](https://json.nlohmann.me/features/parsing/sax_interface/index.md), and [error handling](https://json.nlohmann.me/features/parsing/parse_exceptions/index.md).
- [Comments](https://json.nlohmann.me/features/comments/index.md) and [trailing commas](https://json.nlohmann.me/features/trailing_commas/index.md) — opt-in relaxations of the JSON grammar.

## Accessing and modifying values

- [Element access](https://json.nlohmann.me/features/element_access/index.md) — unchecked ([`operator[]`](https://json.nlohmann.me/features/element_access/unchecked_access/index.md)), checked ([`at`](https://json.nlohmann.me/features/element_access/checked_access/index.md)), and access with a [default value](https://json.nlohmann.me/features/element_access/default_value/index.md).
- [JSON Pointer](https://json.nlohmann.me/features/json_pointer/index.md) — address values deep inside a document with [RFC 6901](https://tools.ietf.org/html/rfc6901) pointers.
- [Iterators](https://json.nlohmann.me/features/iterators/index.md) — traverse arrays and objects.
- [Modifying values](https://json.nlohmann.me/features/modifying_values/index.md) — add, update, merge, and remove elements.
- [JSON Patch and Diff](https://json.nlohmann.me/features/json_patch/index.md) and [JSON Merge Patch](https://json.nlohmann.me/features/merge_patch/index.md) — apply and compute structured changes.

## Converting to and from C++ types

- [Converting values](https://json.nlohmann.me/features/conversions/index.md) — get values out with [`get`](https://json.nlohmann.me/api/basic_json/get/index.md)/[`get_to`](https://json.nlohmann.me/api/basic_json/get_to/index.md), and understand implicit conversions.
- [Arbitrary types conversions](https://json.nlohmann.me/features/arbitrary_types/index.md) — teach the library about your own structs and classes.
- [Specializing enum conversion](https://json.nlohmann.me/features/enum_conversion/index.md) — map enums to strings instead of integers.

## Serializing values

- [Serialization](https://json.nlohmann.me/features/serialization/index.md) — turn a value back into JSON text with [`dump`](https://json.nlohmann.me/api/basic_json/dump/index.md), including pretty-printing and handling of non-ASCII and invalid UTF-8.
- [Binary formats](https://json.nlohmann.me/features/binary_formats/index.md) — encode values more compactly as [BJData](https://json.nlohmann.me/features/binary_formats/bjdata/index.md), [BSON](https://json.nlohmann.me/features/binary_formats/bson/index.md), [CBOR](https://json.nlohmann.me/features/binary_formats/cbor/index.md), [MessagePack](https://json.nlohmann.me/features/binary_formats/messagepack/index.md), or [UBJSON](https://json.nlohmann.me/features/binary_formats/ubjson/index.md).
- [Binary values](https://json.nlohmann.me/features/binary_values/index.md) — store and exchange raw byte sequences.

## How values are stored and configured

- [Types](https://json.nlohmann.me/features/types/index.md) and [number handling](https://json.nlohmann.me/features/types/number_handling/index.md) — how JSON types map to C++ types and how numbers are treated.
- [Object order](https://json.nlohmann.me/features/object_order/index.md) — keep insertion order with [`ordered_json`](https://json.nlohmann.me/api/ordered_json/index.md).
- [Runtime assertions](https://json.nlohmann.me/features/assertions/index.md), [supported macros](https://json.nlohmann.me/features/macros/index.md), the [`nlohmann` namespace](https://json.nlohmann.me/features/namespace/index.md), and [C++ modules](https://json.nlohmann.me/features/modules/index.md) — build-time and runtime configuration.

Looking for a specific function?

This section gives conceptual overviews. For the precise signature, parameters, and return value of a function, see the [API Documentation](https://json.nlohmann.me/api/basic_json/index.md).
