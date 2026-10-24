# v3.10.5

Released on 2022-01-03.

Bug-fix release. All changes are backward-compatible.

- Guards the `std::filesystem` conversions behind compiler-support checks ([`JSON_HAS_FILESYSTEM`](https://json.nlohmann.me/api/macros/json_has_filesystem/index.md)), which can be set to `0` to disable them altogether.

[Full release notes](https://github.com/nlohmann/json/releases/tag/v3.10.5).

## API changes

**Added (1 pages):**

- `macros`: [`JSON_HAS_FILESYSTEM / JSON_HAS_EXPERIMENTAL_FILESYSTEM`](https://json.nlohmann.me/api/macros/json_has_filesystem/index.md)

**Changed:**

- [`std::hash<nlohmann::basic_json>`](https://json.nlohmann.me/api/basic_json/std_hash/index.md): Extended for arbitrary basic_json types in version 3.10.5.
- [`std::swap<basic_json>`](https://json.nlohmann.me/api/basic_json/std_swap/index.md): Extended for arbitrary basic_json types in version 3.10.5.
- [`basic_json::update`](https://json.nlohmann.me/api/basic_json/update/index.md): Added `merge_objects` parameter in 3.10.5.
