# nlohmann::basic_json::to_bson

```
// (1)
static std::vector<std::uint8_t> to_bson(const basic_json& j,
                                         const error_handler_t error_handler = error_handler_t::keep);

// (2)
static void to_bson(const basic_json& j, detail::output_adapter<std::uint8_t> o,
                    const error_handler_t error_handler = error_handler_t::keep);
static void to_bson(const basic_json& j, detail::output_adapter<char> o,
                    const error_handler_t error_handler = error_handler_t::keep);
```

BSON (Binary JSON) is a binary format in which zero or more ordered key/value pairs are stored as a single entity (a so-called document).

1. Returns a byte vector containing the BSON serialization.
1. Writes the BSON serialization to an output adapter.

The exact mapping and its limitations are described on a [dedicated page](https://json.nlohmann.me/features/binary_formats/bson/index.md).

## Parameters

`j` (in) : JSON value to serialize

`o` (in) : output adapter to write serialization to

`error_handler` (in) : how to treat a string or object key in `j` that is not valid UTF-8; see [`error_handler_t`](https://json.nlohmann.me/api/basic_json/error_handler_t/index.md). The default, `keep`, writes the ill-formed bytes to the output as is, as every version of `to_bson` did before this parameter was added; `strict` throws; `replace`/`ignore` sanitize it the same way [`dump`](https://json.nlohmann.me/api/basic_json/dump/index.md) would. If [`JSON_STRICT_BINARY_UTF8`](https://json.nlohmann.me/api/macros/json_strict_binary_utf8/index.md) is enabled, the default is `strict` instead.

## Return value

1. BSON serialization as a byte vector
1. (none)

## Exception safety

Strong guarantee: if an exception is thrown, there are no changes in the JSON value.

## Exceptions

- Throws [`type_error.317`](https://json.nlohmann.me/home/exceptions/#jsonexceptiontype_error317) if the top-level type of the JSON value is not an object; example: `"to serialize to BSON, top-level type must be object, but is string"`
- Throws [`out_of_range.409`](https://json.nlohmann.me/home/exceptions/#jsonexceptionout_of_range409) if a key in the JSON object contains a null byte (code point U+0000); example: `"BSON key cannot contain code point U+0000 (at byte 2)"`
- Throws [`out_of_range.412`](https://json.nlohmann.me/home/exceptions/#jsonexceptionout_of_range412) if the length of a document, array, string, or binary value exceeds the range of the 32-bit BSON length field; example: `"BSON length 2147483661 exceeds maximum of 2147483647"`
- Throws [`out_of_range.415`](https://json.nlohmann.me/home/exceptions/#jsonexceptionout_of_range415) if the subtype of a binary value exceeds 255, the maximum of the BSON binary subtype; example: `"subtype 70000 is too large for the BSON binary subtype (max 255)"`
- Throws [type_error.316](https://json.nlohmann.me/home/exceptions/#jsonexceptiontype_error316) if a string or object key is not valid UTF-8 and `error_handler` is `strict` (the default only if [`JSON_STRICT_BINARY_UTF8`](https://json.nlohmann.me/api/macros/json_strict_binary_utf8/index.md) is enabled)
- Throws [type_error.321](https://json.nlohmann.me/home/exceptions/#jsonexceptiontype_error321) if a value nested in `j` is discarded (the top-level value itself is covered by `type_error.317` above, since it must be an object); example: `"cannot serialize discarded value to BSON"`

## Complexity

Linear in the size of the JSON value `j`. The length prefixes of all nested documents and arrays are computed in one pass before anything is written.

## Examples

Example: serialize a JSON value to BSON

The example shows the serialization of a JSON value to a byte vector in BSON format.

```
#include <iostream>
#include <iomanip>
#include <nlohmann/json.hpp>

using json = nlohmann::json;
using namespace nlohmann::literals;

int main()
{
    // create a JSON value
    json j = R"({"compact": true, "schema": 0})"_json;

    // serialize it to BSON
    std::vector<std::uint8_t> v = json::to_bson(j);

    // print the vector content
    for (auto& byte : v)
    {
        std::cout << "0x" << std::hex << std::setw(2) << std::setfill('0') << (int)byte << " ";
    }
    std::cout << std::endl;
}
```

Output:

```
0x1b 0x00 0x00 0x00 0x08 0x63 0x6f 0x6d 0x70 0x61 0x63 0x74 0x00 0x01 0x10 0x73 0x63 0x68 0x65 0x6d 0x61 0x00 0x00 0x00 0x00 0x00 0x00
```

Example: out_of_range.409 exception

The example shows how serializing a JSON object whose key contains a null byte (U+0000) throws an exception, because BSON keys are null-terminated C strings and cannot contain U+0000 themselves.

```
#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    // create a JSON object whose key contains a null byte (U+0000)
    std::string key = "ab";
    key.push_back('\0');
    key.push_back('c');
    json j = {{key, 1}};

    // exception out_of_range.409
    try
    {
        json::to_bson(j);
    }
    catch (const json::out_of_range& e)
    {
        std::cout << e.what() << '\n';
    }
}
```

Output:

```
[json.exception.out_of_range.409] BSON key cannot contain code point U+0000 (at byte 2)
```

## See also

- [from_bson](https://json.nlohmann.me/api/basic_json/from_bson/index.md) create a JSON value from an input in BSON format
- [to_cbor](https://json.nlohmann.me/api/basic_json/to_cbor/index.md) create a CBOR serialization of a JSON value
- [to_msgpack](https://json.nlohmann.me/api/basic_json/to_msgpack/index.md) create a MessagePack serialization of a JSON value
- [to_ubjson](https://json.nlohmann.me/api/basic_json/to_ubjson/index.md) create a UBJSON serialization of a JSON value
- [to_bjdata](https://json.nlohmann.me/api/basic_json/to_bjdata/index.md) create a BJData serialization of a JSON value
- [to_bon8](https://json.nlohmann.me/api/basic_json/to_bon8/index.md) create a BON8 serialization of a JSON value

## Version history

- Added in version 3.4.0.
- Throws `out_of_range.412` and `out_of_range.415` since version 3.13.0 unreleased.
- Linear in the size of `j`, and no longer limited by the call stack for deeply nested values, since version 3.13.0 unreleased.
- `out_of_range.415` is now detected before anything is written, like the other exceptions above, since version 3.13.0 unreleased.
- Throws `type_error.321` for a discarded value nested in `j` since version 3.13.0 unreleased; previously, it was silently skipped, producing a document whose declared size did not match what was actually written.
- Added `error_handler` parameter in version 3.13.0 unreleased. Its default, `keep`, writes the bytes of a string or object key that is not valid UTF-8 unchanged, as before; `strict` (the default if [`JSON_STRICT_BINARY_UTF8`](https://json.nlohmann.me/api/macros/json_strict_binary_utf8/index.md) is enabled) throws `type_error.316` before anything is written.
