# v2.1.1

Released on 2017-02-25.

Bug-fix release. All changes are backward-compatible.

- Makes number parsing and serialization locale-independent with correct floating-point round-tripping; commits and released files are GPG-signed.

[Full release notes](https://github.com/nlohmann/json/releases/tag/v2.1.1).

## API changes

**Changed:**

- [`basic_json::from_cbor`](https://json.nlohmann.me/api/basic_json/from_cbor/index.md): Parameter `start_index` since version 2.1.1.
- [`basic_json::from_msgpack`](https://json.nlohmann.me/api/basic_json/from_msgpack/index.md): Parameter `start_index` since version 2.1.1.
