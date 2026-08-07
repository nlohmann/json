# Ecosystem

The projects below build on top of `nlohmann::json` rather than merely using it - schema validators, language
bindings, format converters, and similar building blocks. The list is not exhaustive, and is curated rather than
automatically generated. If you maintain or know of a project that belongs here,
[please let me know](mailto:mail@nlohmann.me).

For products, applications, and organizations that use the library, see [Customers](../home/customers.md) instead.

## Schema validation

- [**json-schema-validator**](https://github.com/pboettch/json-schema-validator), a JSON Schema (draft 7) validator
  with human-readable error messages

## Serialization and reflection

- [**nlohmann_json_reflect**](https://github.com/1261385937/nlohmann_json_reflect), a reflection extension for
  (de)serializing nested containers-in-structs-in-containers

## Encodings

- [**base-encode-decode**](https://github.com/saxonnicholls/base-encode-decode), a header-only Base64/32/16/8/4/2
  (and DNA/RNA) encoding library, with an adapter that serializes binary data through `nlohmann::json`

## Language bindings and interop

- [**pybind11_json**](https://github.com/pybind/pybind11_json), a bidirectional type caster between
  `nlohmann::json` and Python objects for [pybind11](https://github.com/pybind/pybind11) bindings
- [**nanobind_json**](https://github.com/ianhbell/nanobind_json), the same idea for
  [nanobind](https://github.com/wjakob/nanobind) bindings
- [**nlohmann_json_qt**](https://github.com/dpurgin/nlohmann_json_qt), deserialization helpers for Qt types
  (`QString`, `QUrl`, `QDateTime`, `QVector`, ...) from `nlohmann::json`
- [**vulkan2json**](https://github.com/Fadis/vulkan2json), serialization and deserialization of Vulkan API structs

## Format converters

- [**tojson**](https://github.com/mircodz/tojson), a header-only converter between YAML/XML documents and
  `nlohmann::json`
- [**json2xml**](https://github.com/testillano/json2xml), a header-only converter from `nlohmann::json` to XML for
  simple configuration documents
