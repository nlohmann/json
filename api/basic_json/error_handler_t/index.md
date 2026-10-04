# nlohmann::basic_json::error_handler_t

```
enum class error_handler_t {
    strict,
    replace,
    ignore,
    keep
};
```

This enumeration is used to choose how to treat ill-formed UTF-8 in a string value or object key:

- [`dump`](https://json.nlohmann.me/api/basic_json/dump/index.md) uses it while serializing a `basic_json` value to text.
- [`to_cbor`](https://json.nlohmann.me/api/basic_json/to_cbor/index.md), [`to_msgpack`](https://json.nlohmann.me/api/basic_json/to_msgpack/index.md), [`to_ubjson`](https://json.nlohmann.me/api/basic_json/to_ubjson/index.md), [`to_bjdata`](https://json.nlohmann.me/api/basic_json/to_bjdata/index.md), and [`to_bson`](https://json.nlohmann.me/api/basic_json/to_bson/index.md) use it while serializing a `basic_json` value to that binary format. Their default is `keep`, as no binary writer checked before this parameter was added. CBOR, UBJSON, BJData, and BSON require valid UTF-8, so for these four the default is `strict` if [`JSON_STRICT_BINARY_UTF8`](https://json.nlohmann.me/api/macros/json_strict_binary_utf8/index.md) is enabled; MessagePack's specification explicitly allows a string to contain ill-formed UTF-8, so `to_msgpack` stays at `keep`. `to_bon8` does not take this parameter: BON8 always validates, since UTF-8 lead bytes are structural to that format.
- [`from_cbor`](https://json.nlohmann.me/api/basic_json/from_cbor/index.md), [`from_msgpack`](https://json.nlohmann.me/api/basic_json/from_msgpack/index.md), [`from_ubjson`](https://json.nlohmann.me/api/basic_json/from_ubjson/index.md), [`from_bjdata`](https://json.nlohmann.me/api/basic_json/from_bjdata/index.md), and [`from_bson`](https://json.nlohmann.me/api/basic_json/from_bson/index.md) use it while parsing that binary format, to decide whether to check a string value or object key for well-formed UTF-8 at all; by default (`keep`) they do not, as no binary reader did before this parameter was added. `from_bon8` does not take this parameter, for the same reason `to_bon8` does not.

Four values are differentiated:

strict : throw a `type_error`/`parse_error` exception in case of invalid UTF-8

replace : replace invalid UTF-8 sequences with U+FFFD (� REPLACEMENT CHARACTER)

ignore : ignore invalid UTF-8 sequences; all valid bytes are copied to the output unchanged, and invalid bytes are dropped

keep : keep invalid UTF-8 sequences unchanged; only meaningful for the binary formats mentioned above, since \[`dump`\] (dump.md) itself must produce text, and `keep` there writes the ill-formed bytes to the output as is, so the result is then not valid UTF-8 (but still equals the input bytes exactly, including around any well-formed characters, which are still escaped as usual)

## Examples

Example

The example below shows how the different values of the `error_handler_t` influence the behavior of [`dump`](https://json.nlohmann.me/api/basic_json/dump/index.md) when reading serializing an invalid UTF-8 sequence.

```
#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    // create JSON value with invalid UTF-8 byte sequence
    json j_invalid = "ä\xA9ü";
    try
    {
        std::cout << j_invalid.dump() << std::endl;
    }
    catch (const json::type_error& e)
    {
        std::cout << e.what() << std::endl;
    }

    std::cout << "string with replaced invalid characters: "
              << j_invalid.dump(-1, ' ', false, json::error_handler_t::replace)
              << "\nstring with ignored invalid characters: "
              << j_invalid.dump(-1, ' ', false, json::error_handler_t::ignore)
              << "\nstring with the invalid byte kept as is (" << j_invalid.dump(-1, ' ', false, json::error_handler_t::keep).size()
              << " bytes, not valid UTF-8 itself)\n";
}
```

Output:

```
[json.exception.type_error.316] invalid UTF-8 byte at index 2: 0xA9
string with replaced invalid characters: "ä�ü"
string with ignored invalid characters: "äü"
string with the invalid byte kept as is (7 bytes, not valid UTF-8 itself)
```

## See also

- [dump](https://json.nlohmann.me/api/basic_json/dump/index.md) serializes a JSON value, with an `error_handler_t` parameter to configure invalid UTF-8 handling
- [Handling invalid UTF-8](https://json.nlohmann.me/features/serialization/#handling-invalid-utf-8) - the article on handling invalid UTF-8

## Version history

- Added in version 3.4.0.
- Added `keep`, and made this enumeration apply to the binary readers and writers in addition to `dump`, in version 3.13.0.
