# v3.7.1

Released on 2019-11-06.

Bug-fix release. All changes are backward-compatible.

- Fixes a segmentation fault when serializing the `std::int64_t` minimum value and fixes [`contains`](https://json.nlohmann.me/api/basic_json/contains/index.md) for JSON pointers.
- Allows [`items`](https://json.nlohmann.me/api/basic_json/items/index.md) with a custom string type and makes `json_pointer::back` `const`.

[Full release notes](https://github.com/nlohmann/json/releases/tag/v3.7.1).

## API changes

No documented API changes.
