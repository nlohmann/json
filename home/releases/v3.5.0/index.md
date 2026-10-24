# v3.5.0

Released on 2018-12-22.

Feature release. All changes are backward-compatible.

- Adds structured-binding support via the [`items`](https://json.nlohmann.me/api/basic_json/items/index.md) function and reading from `FILE*` in the [`parse`](https://json.nlohmann.me/api/basic_json/parse/index.md) function.
- Fixes the `eofbit` handling on input streams and a bug in the BSON SAX parser.

[Full release notes](https://github.com/nlohmann/json/releases/tag/v3.5.0).

## API changes

**Changed:**

- [`basic_json::items`](https://json.nlohmann.me/api/basic_json/items/index.md): Added structured binding support in version 3.5.0.
