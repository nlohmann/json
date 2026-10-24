# v3.1.2

Released on 2018-03-14.

Bug-fix release. All changes are backward-compatible.

- Fixes a memory leak in the parser callback and adds user-defined string-type support to the parser and serializer.

[Full release notes](https://github.com/nlohmann/json/releases/tag/v3.1.2).

## API changes

**Changed:**

- [`basic_json::basic_json`](https://json.nlohmann.me/api/basic_json/basic_json/index.md): Overload 4 added.
- [`basic_json::get`](https://json.nlohmann.me/api/basic_json/get/index.md): Overload 2: Extended to work with other specializations of `basic_json` in version 3.1.2.
