# v3.11.3

Released on 2023-11-28.

Adds features and fixes bugs found in 3.11.2. All changes are backward-compatible.

- Adds a [custom base class](https://json.nlohmann.me/api/basic_json/json_base_class_t/index.md) as a node customization point.
- Adds serialization-only [conversion macros](https://json.nlohmann.me/features/macros/index.md) (`NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_ONLY_SERIALIZE` and `NLOHMANN_DEFINE_TYPE_INTRUSIVE_ONLY_SERIALIZE`) and a clearer parse error for empty input.
- Adds [Bazel](https://json.nlohmann.me/integration/package_managers/#bazel) and [Swift Package Manager](https://json.nlohmann.me/integration/package_managers/#swift-package-manager) build support.
- Fixes custom allocators, a memory leak in [`adl_serializer`](https://json.nlohmann.me/api/adl_serializer/to_json/index.md)'s `to_json`, initializer-list construction when `size_type` is not `int`, and many compiler warnings.

[Full release notes](https://github.com/nlohmann/json/releases/tag/v3.11.3).

## API changes

**Added (2 pages):**

- `basic_json`: [`json_base_class_t`](https://json.nlohmann.me/api/basic_json/json_base_class_t/index.md)
- `macros`: [`JSON_HAS_STATIC_RTTI`](https://json.nlohmann.me/api/macros/json_has_static_rtti/index.md)

**Changed:**

- [`NLOHMANN_DEFINE_TYPE_INTRUSIVE, NLOHMANN_DEFINE_TYPE_INTRUSIVE_WITH_DEFAULT, NLOHMANN_DEFINE_TYPE_INTRUSIVE_ONLY_SERIALIZE`](https://json.nlohmann.me/api/macros/nlohmann_define_type_intrusive/index.md): Overload 3 added.
- [`NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE, NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_WITH_DEFAULT, NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_ONLY_SERIALIZE`](https://json.nlohmann.me/api/macros/nlohmann_define_type_non_intrusive/index.md): Overload 3 added.
