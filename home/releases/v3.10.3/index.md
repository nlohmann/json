# v3.10.3

Released on 2021-10-08.

Fixes more regressions from 3.10.0. All changes are backward-compatible.

- Fixes [extended-diagnostics](https://json.nlohmann.me/api/macros/json_diagnostics/index.md) assertions triggered by [`update`](https://json.nlohmann.me/api/basic_json/update/index.md) and by inserting into arrays.
- Supports custom allocators when writing binary formats into a `std::vector`, and allows conversion from types that only provide `begin()`/`end()`.

[Full release notes](https://github.com/nlohmann/json/releases/tag/v3.10.3).

## API changes

No documented API changes.
