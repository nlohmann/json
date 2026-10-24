# v3.10.0

Released on 2021-08-17.

Feature release. All changes are backward-compatible.

- Adds [extended diagnostic messages](https://json.nlohmann.me/api/macros/json_diagnostics/index.md) ([`JSON_DIAGNOSTICS`](https://json.nlohmann.me/api/macros/json_diagnostics/index.md)) that prepend a JSON pointer to exception messages to pinpoint the offending value.
- Adds a GDB pretty-printer and a [`cbor_tag_handler_t`](https://json.nlohmann.me/api/basic_json/cbor_tag_handler_t/index.md) `store` option to keep CBOR tags as binary subtypes.
- Supports containers with non-default-constructible types and parsing from `std::byte`.
- Adds [`JSON_NO_IO`](https://json.nlohmann.me/api/macros/json_no_io/index.md) to exclude the I/O headers and the [`JSON_HAS_CPP_*`](https://json.nlohmann.me/api/macros/json_has_cpp_11/index.md) macros to override the detected C++ standard.

[Full release notes](https://github.com/nlohmann/json/releases/tag/v3.10.0).

## API changes

**Added (3 pages):**

- `macros`: [`JSON_DIAGNOSTICS`](https://json.nlohmann.me/api/macros/json_diagnostics/index.md), [`JSON_HAS_CPP_11, JSON_HAS_CPP_14, JSON_HAS_CPP_17, JSON_HAS_CPP_20, JSON_HAS_CPP_23, JSON_HAS_CPP_26`](https://json.nlohmann.me/api/macros/json_has_cpp_11/index.md), [`JSON_NO_IO`](https://json.nlohmann.me/api/macros/json_no_io/index.md)

**Changed:**

- [`basic_json::binary`](https://json.nlohmann.me/api/basic_json/binary/index.md): Changed the type of `subtype` from `std::uint8_t` to `binary_t::subtype_type` (`std::uint64_t`) in version 3.10.0.
- [`basic_json::binary_t`](https://json.nlohmann.me/api/basic_json/binary_t/index.md): Changed the type of subtype to `std::uint64_t` in version 3.10.0.
- [`basic_json::cbor_tag_handler_t`](https://json.nlohmann.me/api/basic_json/cbor_tag_handler_t/index.md): Added value `store` in 3.10.0.
- [`byte_container_with_subtype`](https://json.nlohmann.me/api/byte_container_with_subtype/index.md): Changed the type of subtypes to `std::uint64_t` in 3.10.0.
- [`byte_container_with_subtype::subtype`](https://json.nlohmann.me/api/byte_container_with_subtype/subtype/index.md): Fixed return value to properly return `subtype_type(-1)` as documented in version 3.10.0.
