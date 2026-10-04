# nlohmann::basic_json::to_ubjson

```
// (1)
static std::vector<std::uint8_t> to_ubjson(const basic_json& j,
                                           const bool use_size = false,
                                           const bool use_type = false,
                                           const error_handler_t error_handler = error_handler_t::keep);

// (2)
static void to_ubjson(const basic_json& j, detail::output_adapter<std::uint8_t> o,
                      const bool use_size = false, const bool use_type = false,
                      const error_handler_t error_handler = error_handler_t::keep);
static void to_ubjson(const basic_json& j, detail::output_adapter<char> o,
                      const bool use_size = false, const bool use_type = false,
                      const error_handler_t error_handler = error_handler_t::keep);
```

Serializes a given JSON value `j` to a byte vector using the UBJSON (Universal Binary JSON) serialization format. UBJSON aims to be more compact than JSON itself, yet more efficient to parse.

1. Returns a byte vector containing the UBJSON serialization.
1. Writes the UBJSON serialization to an output adapter.

The exact mapping and its limitations are described on a [dedicated page](https://json.nlohmann.me/features/binary_formats/ubjson/index.md).

## Parameters

`j` (in) : JSON value to serialize

`o` (in) : output adapter to write serialization to

`use_size` (in) : whether to add size annotations to container types; optional, `false` by default.

`use_type` (in) : whether to add type annotations to container types (must be combined with `use_size = true`); optional, `false` by default.

`error_handler` (in) : how to treat a string or object key in `j` that is not valid UTF-8; see [`error_handler_t`](https://json.nlohmann.me/api/basic_json/error_handler_t/index.md). The default, `keep`, writes the ill-formed bytes to the output as is, as every version of `to_ubjson` did before this parameter was added; `strict` throws; `replace`/`ignore` sanitize it the same way [`dump`](https://json.nlohmann.me/api/basic_json/dump/index.md) would. If [`JSON_STRICT_BINARY_UTF8`](https://json.nlohmann.me/api/macros/json_strict_binary_utf8/index.md) is enabled, the default is `strict` instead.

## Return value

1. UBJSON serialization as a byte vector
1. (none)

## Exception safety

Strong guarantee: if an exception is thrown, there are no changes in the JSON value.

## Exceptions

- Throws [`other_error.502`](https://json.nlohmann.me/home/exceptions/#jsonexceptionother_error502) if `use_type` is true and `use_size` is false, and `j` contains a non-empty array, object, or binary value.
- Throws [type_error.316](https://json.nlohmann.me/home/exceptions/#jsonexceptiontype_error316) if a string or object key in `j` is not valid UTF-8 and `error_handler` is `strict` (the default only if [`JSON_STRICT_BINARY_UTF8`](https://json.nlohmann.me/api/macros/json_strict_binary_utf8/index.md) is enabled)

## Complexity

Linear in the size of the JSON value `j`.

## Examples

Example: serialize a JSON value to UBJSON

The example shows the serialization of a JSON value to a byte vector in UBJSON format.

```
#include <iostream>
#include <iomanip>
#include <nlohmann/json.hpp>

using json = nlohmann::json;
using namespace nlohmann::literals;

// function to print UBJSON's diagnostic format
void print_byte(uint8_t byte)
{
    if (32 < byte and byte < 128)
    {
        std::cout << (char)byte;
    }
    else
    {
        std::cout << (int)byte;
    }
}

int main()
{
    // create a JSON value
    json j = R"({"compact": true, "schema": false})"_json;

    // serialize it to UBJSON
    std::vector<std::uint8_t> v = json::to_ubjson(j);

    // print the vector content
    for (auto& byte : v)
    {
        print_byte(byte);
    }
    std::cout << std::endl;

    // create an array of numbers
    json array = {1, 2, 3, 4, 5, 6, 7, 8};

    // serialize it to UBJSON using default representation
    std::vector<std::uint8_t> v_array = json::to_ubjson(array);
    // serialize it to UBJSON using size optimization
    std::vector<std::uint8_t> v_array_size = json::to_ubjson(array, true);
    // serialize it to UBJSON using type optimization
    std::vector<std::uint8_t> v_array_size_and_type = json::to_ubjson(array, true, true);

    // print the vector contents
    for (auto& byte : v_array)
    {
        print_byte(byte);
    }
    std::cout << std::endl;

    for (auto& byte : v_array_size)
    {
        print_byte(byte);
    }
    std::cout << std::endl;

    for (auto& byte : v_array_size_and_type)
    {
        print_byte(byte);
    }
    std::cout << std::endl;
}
```

Output:

```
{i7compactTi6schemaF}
[i1i2i3i4i5i6i7i8]
[#i8i1i2i3i4i5i6i7i8
[$i#i812345678
```

Example: other_error.502 exception

The example shows how requesting type annotations (`use_type`) without size annotations (`use_size`) throws an exception, because type-optimized containers can only be read back with a preceding size.

```
#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    // create a non-empty JSON array
    json j = {1, 2, 3};

    // exception other_error.502
    try
    {
        json::to_ubjson(j, false, true);
    }
    catch (const json::other_error& e)
    {
        std::cout << e.what() << '\n';
    }
}
```

Output:

```
[json.exception.other_error.502] use_type requires use_size = true
```

## See also

- [from_ubjson](https://json.nlohmann.me/api/basic_json/from_ubjson/index.md) create a JSON value from an input in UBJSON format
- [to_cbor](https://json.nlohmann.me/api/basic_json/to_cbor/index.md) create a CBOR serialization of a JSON value
- [to_msgpack](https://json.nlohmann.me/api/basic_json/to_msgpack/index.md) create a MessagePack serialization of a JSON value
- [to_bson](https://json.nlohmann.me/api/basic_json/to_bson/index.md) create a BSON serialization of a JSON value
- [to_bjdata](https://json.nlohmann.me/api/basic_json/to_bjdata/index.md) create a BJData serialization of a JSON value
- [to_bon8](https://json.nlohmann.me/api/basic_json/to_bon8/index.md) create a BON8 serialization of a JSON value

## Version history

- Added in version 3.1.0.
- Added `error_handler` parameter in version 3.13.0 unreleased. Its default, `keep`, writes the bytes of a string or object key that is not valid UTF-8 unchanged, as before; `strict` (the default if [`JSON_STRICT_BINARY_UTF8`](https://json.nlohmann.me/api/macros/json_strict_binary_utf8/index.md) is enabled) throws `type_error.316`.
