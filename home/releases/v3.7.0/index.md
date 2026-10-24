# v3.7.0

Released on 2019-07-28.

Convenience features and house-keeping. All changes are backward-compatible.

- Adds a [`contains`](https://json.nlohmann.me/api/basic_json/contains/index.md) overload that checks a JSON pointer without throwing, a generic `to_string`, and a return value for [`emplace_back`](https://json.nlohmann.me/api/basic_json/emplace_back/index.md).

[Full release notes](https://github.com/nlohmann/json/releases/tag/v3.7.0).

## API changes

**Changed:**

- [`basic_json::contains`](https://json.nlohmann.me/api/basic_json/contains/index.md): Overload 3 added.
- [`basic_json::emplace_back`](https://json.nlohmann.me/api/basic_json/emplace_back/index.md): Returns reference since 3.7.0.
