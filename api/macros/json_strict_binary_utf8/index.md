# JSON_STRICT_BINARY_UTF8

```
#define JSON_STRICT_BINARY_UTF8 /* value */
```

When defined to `1`, the `error_handler` parameter of the binary writers [`to_cbor`](https://json.nlohmann.me/api/basic_json/to_cbor/index.md), [`to_ubjson`](https://json.nlohmann.me/api/basic_json/to_ubjson/index.md), [`to_bjdata`](https://json.nlohmann.me/api/basic_json/to_bjdata/index.md), and [`to_bson`](https://json.nlohmann.me/api/basic_json/to_bson/index.md) defaults to [`error_handler_t::strict`](https://json.nlohmann.me/api/basic_json/error_handler_t/index.md) instead of `error_handler_t::keep`. These writers then check every string value and object key for valid UTF-8 and throw [`type_error.316`](https://json.nlohmann.me/home/exceptions/#jsonexceptiontype_error316) for ill-formed UTF-8, like [`dump`](https://json.nlohmann.me/api/basic_json/dump/index.md) does. Without it, they write the bytes unchanged. An `error_handler` passed explicitly always takes precedence.

The macro does not affect:

- [`to_msgpack`](https://json.nlohmann.me/api/basic_json/to_msgpack/index.md): the MessagePack specification allows a `str` value to contain bytes that are not valid UTF-8, so its `error_handler` always defaults to `keep`.
- [`to_bon8`](https://json.nlohmann.me/api/basic_json/to_bon8/index.md): BON8 always checks, because the UTF-8 lead bytes mark where a string ends.
- The binary readers ([`from_cbor`](https://json.nlohmann.me/api/basic_json/from_cbor/index.md), [`from_msgpack`](https://json.nlohmann.me/api/basic_json/from_msgpack/index.md), [`from_ubjson`](https://json.nlohmann.me/api/basic_json/from_ubjson/index.md), [`from_bjdata`](https://json.nlohmann.me/api/basic_json/from_bjdata/index.md), [`from_bson`](https://json.nlohmann.me/api/basic_json/from_bson/index.md)): none of these formats requires a decoder to reject ill-formed UTF-8, so they always return the bytes unchanged.

## Default definition

The default value is `0` (disabled, the behavior of version 3.12.0 and earlier is preserved).

```
#define JSON_STRICT_BINARY_UTF8 0
```

## Notes

Background

CBOR, UBJSON, BJData, and BSON all require strings to be UTF-8. Up to version 3.12.0, the writers did not check this, so they could produce output that other decoders reject. Checking by default would break code that stores other encodings (for instance ISO 8859-1) in a string and only ever writes it to a binary format. You can pass `error_handler_t::strict` to each call, or use this macro to check by default ahead of version 4.0.0, where `strict` is planned to become the default (see [#5529](https://github.com/nlohmann/json/issues/5529) and [#5651](https://github.com/nlohmann/json/issues/5651)).

Opt-in only

This macro must be defined **before** including `<nlohmann/json.hpp>`. Defining it after the include has no effect.

ABI compatibility

The value of this macro is encoded in the [namespace](https://json.nlohmann.me/features/namespace/index.md) (tag `_sbu8`), resulting in distinct symbol names. Translation units compiled with and without it can therefore be linked into the same program without One Definition Rule (ODR) violations, but they cannot exchange instances of library types.

## Examples

Example: default behavior (macro not defined)

Without the macro, the bytes are written unchanged:

```
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    auto v = json::to_cbor(json("\xFF"));
    // v is {0x61, 0xFF}
}
```

Example: opt-in check (macro defined to 1)

With the macro, ill-formed UTF-8 is rejected:

```
#define JSON_STRICT_BINARY_UTF8 1
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    auto v = json::to_cbor(json("\xFF"));
    // throws type_error.316: invalid UTF-8 byte at index 0: 0xFF
}
```

## See also

- [**to_cbor**](https://json.nlohmann.me/api/basic_json/to_cbor/index.md) - create a CBOR serialization of a JSON value
- [**to_ubjson**](https://json.nlohmann.me/api/basic_json/to_ubjson/index.md) - create a UBJSON serialization of a JSON value
- [**to_bjdata**](https://json.nlohmann.me/api/basic_json/to_bjdata/index.md) - create a BJData serialization of a JSON value
- [**to_bson**](https://json.nlohmann.me/api/basic_json/to_bson/index.md) - create a BSON serialization of a JSON value
- [**error_handler_t**](https://json.nlohmann.me/api/basic_json/error_handler_t/index.md) - how [`dump`](https://json.nlohmann.me/api/basic_json/dump/index.md) treats ill-formed UTF-8

## Version history

- Added in version 3.13.0 unreleased.
- Planned to become the default (with the macro removed) in version 4.0.0.
