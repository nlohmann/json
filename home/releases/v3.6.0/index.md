# v3.6.0

Released on 2019-03-20.

Feature release. All changes are backward-compatible.

- Reworks the [JSON pointer](https://json.nlohmann.me/features/json_pointer/index.md) interface (`operator/`, `push_back`, `parent_pointer`, …).
- Adds a [`contains`](https://json.nlohmann.me/api/basic_json/contains/index.md) function to test for an object key and greatly improves the performance of integer serialization.

[Full release notes](https://github.com/nlohmann/json/releases/tag/v3.6.0).

## API changes

**Added (5 pages):**

- `basic_json`: [`contains`](https://json.nlohmann.me/api/basic_json/contains/index.md)
- `json_pointer`: [`back`](https://json.nlohmann.me/api/json_pointer/back/index.md), [`operator/`](https://json.nlohmann.me/api/json_pointer/operator_slash/index.md), [`operator/=`](https://json.nlohmann.me/api/json_pointer/operator_slasheq/index.md), [`push_back`](https://json.nlohmann.me/api/json_pointer/push_back/index.md)
