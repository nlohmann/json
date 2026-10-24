# v3.1.0

Released on 2018-02-01.

Feature release. All changes are backward-compatible.

- Adds [UBJSON](https://json.nlohmann.me/features/binary_formats/ubjson/index.md) read/write support and [JSON Merge Patch](https://json.nlohmann.me/features/merge_patch/index.md) via [`merge_patch`](https://json.nlohmann.me/api/basic_json/merge_patch/index.md).
- Switches to the Grisu2 algorithm for short, round-trippable floating-point output, and splits the header into [multiple files](https://json.nlohmann.me/integration/index.md) with a forward-declaration header.

[Full release notes](https://github.com/nlohmann/json/releases/tag/v3.1.0).

## API changes

**Added (6 pages):**

- `basic_json`: [`from_ubjson`](https://json.nlohmann.me/api/basic_json/from_ubjson/index.md), [`items`](https://json.nlohmann.me/api/basic_json/items/index.md), [`merge_patch`](https://json.nlohmann.me/api/basic_json/merge_patch/index.md), [`to_ubjson`](https://json.nlohmann.me/api/basic_json/to_ubjson/index.md)
- `macros`: [`JSON_CATCH_USER, JSON_THROW_USER, JSON_TRY_USER`](https://json.nlohmann.me/api/macros/json_throw_user/index.md), [`NLOHMANN_JSON_VERSION_MAJOR, NLOHMANN_JSON_VERSION_MINOR, NLOHMANN_JSON_VERSION_PATCH`](https://json.nlohmann.me/api/macros/nlohmann_json_version_major/index.md)
