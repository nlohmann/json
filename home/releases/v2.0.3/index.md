# v2.0.3

Released on 2016-08-31.

Generalizes the parser to accept any contiguous sequence of one-byte elements and deprecates the input-stream constructor in favor of the [`parse`](https://json.nlohmann.me/api/basic_json/parse/index.md) function. All changes are backward-compatible. [Full release notes](https://github.com/nlohmann/json/releases/tag/v2.0.3).

## API changes

**Changed:**

- [`basic_json::parse`](https://json.nlohmann.me/api/basic_json/parse/index.md): Overload for contiguous containers (1) added in version 2.0.3.
