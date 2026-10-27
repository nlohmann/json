# Features

This section describes the features of the library in detail. If you are new to the library, the pages below are
roughly ordered along a typical workflow: create or parse a value, access and modify it, convert it to and from your own
C++ types, and finally serialize it again.

## Creating and reading values

- [Creating JSON values](creating_values.md) — build values from literals, initializer lists, and STL containers, and
  understand the `#!cpp {}` vs. `#!cpp []` ambiguity.
- [Parsing](parsing/index.md) — read a JSON value from a string, file, or stream, including
  [JSON Lines](parsing/json_lines.md), [callbacks](parsing/parser_callbacks.md), the
  [SAX interface](parsing/sax_interface.md), [error handling](parsing/parse_exceptions.md),
  [large and partial input](parsing/large_and_partial_input.md), and
  [parsing untrusted input](parsing/untrusted_input.md).
- [Zero-copy JSON views](json_view.md) — read a JSON text through a flat index instead of building a `json` tree;
  strings and numbers stay in the input and are only decoded when needed.
- [Editable documents](json_view.md#editing-a-document) — modify a parsed document without building a `json` tree.
- [Images](json_view.md#images) — save a parsed document and load it again without parsing it.
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
- [Recipes for common types](type_recipes.md) — convert smart pointers, `std::variant`, `std::chrono` types, and class
  hierarchies, which the library deliberately leaves to you.
- [Specializing enum conversion](enum_conversion.md) — map enums to strings instead of integers.

## Serializing values

- [Serialization](serialization.md) — turn a value back into JSON text with [`dump`](../api/basic_json/dump.md),
  including pretty-printing and handling of non-ASCII and invalid UTF-8.
- [Binary formats](binary_formats/index.md) — encode values more compactly as
  [BJData](binary_formats/bjdata.md), [BON8](binary_formats/bon8.md), [BSON](binary_formats/bson.md),
  [CBOR](binary_formats/cbor.md), [MessagePack](binary_formats/messagepack.md), or [UBJSON](binary_formats/ubjson.md).
- [Binary values](binary_values.md) — store and exchange raw byte sequences.

## How values are stored and configured

- [Types](types/index.md) and [number handling](types/number_handling.md) — how JSON types map to C++ types and how
  numbers are treated.
- [Template parameter requirements](types/template_parameters.md) — what a type passed as one of `basic_json`'s
  template parameters has to provide.
- [Object order](object_order.md) — keep insertion order with [`ordered_json`](../api/ordered_json.md).
- [Performance](performance.md) — practical advice on parsing, memory use, serialization, and compile times.
- [Working without exceptions](no_exceptions.md) — what to use when exceptions are unwanted or unavailable.
- [Runtime assertions](assertions.md), [supported macros](macros.md), the [`nlohmann` namespace](namespace.md), and
  [C++ modules](modules.md) — build-time and runtime configuration.

!!! tip "Looking for a specific function?"

    This section gives conceptual overviews. For the precise signature, parameters, and return value of a function, see
    the [API Documentation](../api/basic_json/index.md).

## See also

- [API documentation](../api/basic_json/index.md) - reference of all classes and functions
- [FAQ](../home/faq.md) - answers to common questions
- [Exceptions](../home/exceptions.md) - all exceptions and their error codes
- [Design goals](../home/design_goals.md) - the goals behind the library
- [Integration](../integration/index.md) - how to add the library to a project
- [Macros](../api/macros/index.md) - reference of all macros
- [`json_pointer`](../api/json_pointer/index.md) - the JSON Pointer class
- [`adl_serializer`](../api/adl_serializer/index.md) - customization point for type conversions
- [`json_sax`](../api/json_sax/index.md) - interface of the SAX parser events
- [`json_document`](../api/json_document.md) - an immutable document with a flat index
- [`json_view`](../api/json_view.md) - a non-owning view of a value in a document
- [`byte_container_with_subtype`](../api/byte_container_with_subtype/index.md) - binary values with a subtype
- [`ordered_json`](../api/ordered_json.md) - a JSON type preserving insertion order
- [Supported Macros](macros.md) - all supported macros
- [`nlohmann` Namespace](namespace.md) - the library namespace
