# v1.1.0

Released on 2016-01-24.

Bug-fix and feature release. All changes are backward-compatible.

- Improves floating-point round-tripping, adds a `get_ref` accessor for stored values, and introduces runtime [assertions](https://json.nlohmann.me/features/assertions/index.md).

[Full release notes](https://github.com/nlohmann/json/releases/tag/v1.1.0).

## API changes

**Added (1 pages):**

- `basic_json`: [`get_ref`](https://json.nlohmann.me/api/basic_json/get_ref/index.md)

**Changed:**

- [`basic_json::operator[]`](https://json.nlohmann.me/api/basic_json/operator%5B%5D/index.md): Overload 2: Added overloads for `T* key` in version 1.1.0.
