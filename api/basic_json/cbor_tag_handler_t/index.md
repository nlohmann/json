# nlohmann::basic_json::cbor_tag_handler_t

```
enum class cbor_tag_handler_t
{
    error,
    ignore,
    store
};
```

This enumeration is used in the [`from_cbor`](https://json.nlohmann.me/api/basic_json/from_cbor/index.md) function to choose how to treat tags:

error : throw a `parse_error` exception in case of a tag

ignore : ignore tags

store : store tagged byte strings (for bytes 0xd8..0xdb) as binary values with the tag as subtype; other tagged values are read as if the tag were ignored. If several tags precede a byte string, only the innermost one is stored.

## Examples

Example

The example below shows how the different values of the `cbor_tag_handler_t` influence the behavior of [`from_cbor`](https://json.nlohmann.me/api/basic_json/from_cbor/index.md) when reading a tagged byte string.

```
#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    // tagged byte string
    std::vector<std::uint8_t> vec = {{0xd8, 0x42, 0x44, 0xcA, 0xfe, 0xba, 0xbe}};

    // cbor_tag_handler_t::error throws
    try
    {
        auto b_throw_on_tag = json::from_cbor(vec, true, true, json::cbor_tag_handler_t::error);
    }
    catch (const json::parse_error& e)
    {
        std::cout << e.what() << std::endl;
    }

    // cbor_tag_handler_t::ignore ignores the tag
    auto b_ignore_tag = json::from_cbor(vec, true, true, json::cbor_tag_handler_t::ignore);
    std::cout << b_ignore_tag << std::endl;

    // cbor_tag_handler_t::store stores the tag as binary subtype
    auto b_store_tag = json::from_cbor(vec, true, true, json::cbor_tag_handler_t::store);
    std::cout << b_store_tag << std::endl;
}
```

Output:

```
[json.exception.parse_error.112] parse error at byte 1: syntax error while parsing CBOR value: invalid byte: 0xD8
{"bytes":[202,254,186,190],"subtype":null}
{"bytes":[202,254,186,190],"subtype":66}
```

## See also

- [from_cbor](https://json.nlohmann.me/api/basic_json/from_cbor/index.md) deserializes a JSON value from CBOR
- [input_format_t](https://json.nlohmann.me/api/basic_json/input_format_t/index.md) the enumeration of supported input formats
- [CBOR](https://json.nlohmann.me/features/binary_formats/cbor/index.md) - the article on the CBOR format

## Version history

- Added in version 3.9.0. Added value `store` in 3.10.0.
