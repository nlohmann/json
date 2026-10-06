# JSON_DELETE_DEPRECATED_FUNCTIONS

```
#define JSON_DELETE_DEPRECATED_FUNCTIONS /* value */
```

When defined to `1`, all [deprecated functions](https://json.nlohmann.me/community/roadmap/#removal-of-deprecated-functions) of the library are declared as deleted (`= delete`) instead of only being marked as deprecated. Code that still calls one of them no longer compiles. This way, you can find all calls that need to be replaced before version 4.0.0 unreleased removes these functions; the [migration guide](https://json.nlohmann.me/integration/migration_guide/#replace-deprecated-functions) describes how.

A deleted function, unlike a removed one, still takes part in overload resolution. A call that would select it therefore fails to compile instead of silently selecting another overload. This matters for the deprecated `from_*(ptr, len)` overloads of [`from_cbor`](https://json.nlohmann.me/api/basic_json/from_cbor/index.md), [`from_msgpack`](https://json.nlohmann.me/api/basic_json/from_msgpack/index.md), [`from_ubjson`](https://json.nlohmann.me/api/basic_json/from_ubjson/index.md), [`from_bjdata`](https://json.nlohmann.me/api/basic_json/from_bjdata/index.md), [`from_bon8`](https://json.nlohmann.me/api/basic_json/from_bon8/index.md), and [`from_bson`](https://json.nlohmann.me/api/basic_json/from_bson/index.md): without them, a call like `from_cbor(ptr, len)` would compile, read `ptr` as a NUL-terminated string, and convert `len` to the `strict` parameter.

The macro does not affect the deprecated legacy comparison of discarded values, which is controlled by [`JSON_USE_LEGACY_DISCARDED_VALUE_COMPARISON`](https://json.nlohmann.me/api/macros/json_use_legacy_discarded_value_comparison/index.md).

## Default definition

The default value is `0` (disabled, the deprecated functions can still be called, and the compiler warns about it).

```
#define JSON_DELETE_DEPRECATED_FUNCTIONS 0
```

## Notes

CMake option

The macro can also be set with the CMake option [`JSON_DeleteDeprecatedFunctions`](https://json.nlohmann.me/integration/cmake/#json_deletedeprecatedfunctions) (`OFF` by default).

Opt-in only

This macro must be defined **before** including `<nlohmann/json.hpp>`. Defining it after the include has no effect. Define it for the whole project to avoid different declarations of the same class in different translation units.

ABI compatibility

The macro only turns calls that compile into calls that do not; it does not change the layout or the behavior of any type. Its value is therefore not encoded in the [namespace](https://json.nlohmann.me/features/namespace/index.md).

## Examples

Example: default behavior (macro not defined)

Without the macro, the deprecated overload is called, and the compiler warns about it:

```
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    const std::vector<std::uint8_t> v = {0x82, 0x01, 0x02};
    auto j = json::from_cbor(v.data(), v.size());
    // warning: 'from_cbor' is deprecated: Since 3.8.0; use from_cbor(ptr, ptr + len)
}
```

Example: deleted deprecated functions (macro defined to 1)

With the macro, the call does not compile:

```
#define JSON_DELETE_DEPRECATED_FUNCTIONS 1
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    const std::vector<std::uint8_t> v = {0x82, 0x01, 0x02};
    auto j = json::from_cbor(v.data(), v.size());
    // error: call to deleted function 'from_cbor'
}
```

## See also

- [Roadmap: removal of deprecated functions](https://json.nlohmann.me/community/roadmap/#removal-of-deprecated-functions) - the deprecated functions and the version they were deprecated in
- [Migration guide: replace deprecated functions](https://json.nlohmann.me/integration/migration_guide/#replace-deprecated-functions) - how to replace each deprecated function

## Version history

- Added in version 3.13.0 unreleased.
- Planned to be removed in version 4.0.0, which removes the deprecated functions. The deprecated `from_*(ptr, len)` overloads stay deleted in version 4.0.0 unreleased.
