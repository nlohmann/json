# v3.11.1

Released on 2022-08-01.

Fixes a regression from 3.11.0. All changes are backward-compatible.

- Restores the global [user-defined string literals](https://json.nlohmann.me/api/macros/json_use_global_udls/index.md) [`operator""_json`](https://json.nlohmann.me/api/operator_literal_json/index.md) and [`operator""_json_pointer`](https://json.nlohmann.me/api/operator_literal_json_pointer/index.md), which 3.11.0 had moved into a namespace by default.

[Full release notes](https://github.com/nlohmann/json/releases/tag/v3.11.1).

## API changes

No documented API changes.
