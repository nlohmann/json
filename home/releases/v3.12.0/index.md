# v3.12.0

Released on 2025-04-11.

Fixes bugs found in 3.11.3 and adds several features. No public API was removed or renamed.

- Adds diagnostic byte positions via [`JSON_DIAGNOSTIC_POSITIONS`](https://json.nlohmann.me/api/macros/json_diagnostic_positions/index.md), exposed through the new [`start_pos`](https://json.nlohmann.me/api/basic_json/start_pos/index.md) and [`end_pos`](https://json.nlohmann.me/api/basic_json/end_pos/index.md) member functions.
- Makes the [conversion macros](https://json.nlohmann.me/features/arbitrary_types/#simplify-your-life-with-macros) templated (so they also work with [`ordered_json`](https://json.nlohmann.me/api/ordered_json/index.md)) and adds [`NLOHMANN_DEFINE_DERIVED_TYPE`](https://json.nlohmann.me/api/macros/nlohmann_define_derived_type/index.md) for derived classes.
- Adds `std::optional` support (C++17) and lets [`patch`](https://json.nlohmann.me/api/basic_json/patch/index.md), [`diff`](https://json.nlohmann.me/api/basic_json/diff/index.md), and [`flatten`](https://json.nlohmann.me/api/basic_json/flatten/index.md) work with arbitrary string types.
- Extends the [binary formats](https://json.nlohmann.me/features/binary_formats/index.md): [BJData](https://json.nlohmann.me/features/binary_formats/bjdata/index.md) draft 3 and unsigned 64-bit integers for [BSON](https://json.nlohmann.me/features/binary_formats/bson/index.md).
- Adds multidimensional C-array conversion and UTF-8 encoded `std::filesystem::path` conversions, and raises the minimum [CMake](https://json.nlohmann.me/integration/cmake/index.md) version to 3.5 and supports CMake 4.0.

[Full release notes](https://github.com/nlohmann/json/releases/tag/v3.12.0).

## API changes

**Added (5 pages):**

- `basic_json`: [`bjdata_version_t`](https://json.nlohmann.me/api/basic_json/bjdata_version_t/index.md), [`end_pos`](https://json.nlohmann.me/api/basic_json/end_pos/index.md), [`start_pos`](https://json.nlohmann.me/api/basic_json/start_pos/index.md)
- `macros`: [`JSON_DIAGNOSTIC_POSITIONS`](https://json.nlohmann.me/api/macros/json_diagnostic_positions/index.md), [`nlohmann_define_derived_type`](https://json.nlohmann.me/api/macros/nlohmann_define_derived_type/index.md)

**Changed:**

- [`basic_json::accept`](https://json.nlohmann.me/api/basic_json/accept/index.md): Changed [runtime assertion](https://json.nlohmann.me/features/assertions/index.md) in case of `FILE*` null pointers to exception in version 3.12.0.
- [`basic_json::parse`](https://json.nlohmann.me/api/basic_json/parse/index.md): Changed [runtime assertion](https://json.nlohmann.me/features/assertions/index.md) in case of `FILE*` null pointers to exception in version 3.12.0.
- [`basic_json::to_bjdata`](https://json.nlohmann.me/api/basic_json/to_bjdata/index.md): BJData version parameter (for draft3 binary encoding) added in version 3.12.0.
- [`JSON_HAS_CPP_11, JSON_HAS_CPP_14, JSON_HAS_CPP_17, JSON_HAS_CPP_20, JSON_HAS_CPP_23, JSON_HAS_CPP_26`](https://json.nlohmann.me/api/macros/json_has_cpp_11/index.md): Added `JSON_HAS_CPP_23` in version 3.12.0.
- [`NLOHMANN_JSON_NAMESPACE`](https://json.nlohmann.me/api/macros/nlohmann_json_namespace/index.md): Added the ABI tag `_dp` in version 3.12.0, and the ABI tags `_bics`, `_psp`, `_snul`, `_sbu8`, `_ekmo`, `_dsbs`, `_dufio`, and `_ns` in version 3.13.0 unreleased; see [`nlohmann` Namespace](https://json.nlohmann.me/features/namespace/#structure).
