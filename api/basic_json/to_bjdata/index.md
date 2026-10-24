# nlohmann::basic_json::to_bjdata

```
// (1)
static std::vector<std::uint8_t> to_bjdata(const basic_json& j,
                                           const bool use_size = false,
                                           const bool use_type = false,
                                           const bjdata_version_t version = bjdata_version_t::draft2,
                                           const error_handler_t error_handler = error_handler_t::keep);

// (2)
static void to_bjdata(const basic_json& j, detail::output_adapter<std::uint8_t> o,
                      const bool use_size = false, const bool use_type = false,
                      const bjdata_version_t version = bjdata_version_t::draft2,
                      const error_handler_t error_handler = error_handler_t::keep);
static void to_bjdata(const basic_json& j, detail::output_adapter<char> o,
                      const bool use_size = false, const bool use_type = false,
                      const bjdata_version_t version = bjdata_version_t::draft2,
                      const error_handler_t error_handler = error_handler_t::keep);
```

Serializes a given JSON value `j` to a byte vector using the BJData (Binary JData) serialization format. BJData aims to be more compact than JSON itself, yet more efficient to parse.

1. Returns a byte vector containing the BJData serialization.
1. Writes the BJData serialization to an output adapter.

The exact mapping and its limitations are described on a [dedicated page](https://json.nlohmann.me/features/binary_formats/bjdata/index.md).

## Parameters

`j` (in) : JSON value to serialize

`o` (in) : output adapter to write serialization to

`use_size` (in) : whether to add size annotations to container types; optional, `false` by default.

`use_type` (in) : whether to add type annotations to container types (must be combined with `use_size = true`); optional, `false` by default.

`version` (in) : which version of BJData to use (see note on "Binary values" on [BJData](https://json.nlohmann.me/features/binary_formats/bjdata/index.md)); optional, `bjdata_version_t::draft2` by default.

`error_handler` (in) : how to treat a string or object key in `j` that is not valid UTF-8; see [`error_handler_t`](https://json.nlohmann.me/api/basic_json/error_handler_t/index.md). The default, `keep`, writes the ill-formed bytes to the output as is, as every version of `to_bjdata` did before this parameter was added; `strict` throws; `replace`/`ignore` sanitize it the same way [`dump`](https://json.nlohmann.me/api/basic_json/dump/index.md) would. If [`JSON_STRICT_BINARY_UTF8`](https://json.nlohmann.me/api/macros/json_strict_binary_utf8/index.md) is enabled, the default is `strict` instead.

## Return value

1. BJData serialization as byte vector
1. (none)

## Exception safety

Strong guarantee: if an exception is thrown, there are no changes in the JSON value.

## Exceptions

- Throws [`other_error.502`](https://json.nlohmann.me/home/exceptions/#jsonexceptionother_error502) if `use_type` is true and `use_size` is false, and `j` contains a non-empty array, object, or binary value.
- Throws [type_error.316](https://json.nlohmann.me/home/exceptions/#jsonexceptiontype_error316) if a string or object key in `j` is not valid UTF-8 and `error_handler` is `strict` (the default only if [`JSON_STRICT_BINARY_UTF8`](https://json.nlohmann.me/api/macros/json_strict_binary_utf8/index.md) is enabled)
- Throws [type_error.321](https://json.nlohmann.me/home/exceptions/#jsonexceptiontype_error321) if `j` or a value nested in it is discarded; example: `"cannot serialize discarded value to BJData"`

## Complexity

Linear in the size of the JSON value `j`.

## Examples

Example: serialize a JSON value to BJData

The example shows the serialization of a JSON value to a byte vector in BJData format.

```
#include <iostream>
#include <iomanip>
#include <nlohmann/json.hpp>

using json = nlohmann::json;
using namespace nlohmann::literals;

// function to print BJData's diagnostic format
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

    // serialize it to BJData
    std::vector<std::uint8_t> v = json::to_bjdata(j);

    // print the vector content
    for (auto& byte : v)
    {
        print_byte(byte);
    }
    std::cout << std::endl;

    // create an array of numbers
    json array = {1, 2, 3, 4, 5, 6, 7, 8};

    // serialize it to BJData using default representation
    std::vector<std::uint8_t> v_array = json::to_bjdata(array);
    // serialize it to BJData using size optimization
    std::vector<std::uint8_t> v_array_size = json::to_bjdata(array, true);
    // serialize it to BJData using type optimization
    std::vector<std::uint8_t> v_array_size_and_type = json::to_bjdata(array, true, true);

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
        json::to_bjdata(j, false, true);
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

- [from_bjdata](https://json.nlohmann.me/api/basic_json/from_bjdata/index.md) create a JSON value from an input in BJData format
- [to_cbor](https://json.nlohmann.me/api/basic_json/to_cbor/index.md) create a CBOR serialization of a JSON value
- [to_msgpack](https://json.nlohmann.me/api/basic_json/to_msgpack/index.md) create a MessagePack serialization of a JSON value
- [to_bson](https://json.nlohmann.me/api/basic_json/to_bson/index.md) create a BSON serialization of a JSON value
- [to_ubjson](https://json.nlohmann.me/api/basic_json/to_ubjson/index.md) create a UBJSON serialization of a JSON value
- [to_bon8](https://json.nlohmann.me/api/basic_json/to_bon8/index.md) create a BON8 serialization of a JSON value

## Version history

- Added in version 3.11.0.
- BJData version parameter (for draft3 binary encoding) added in version 3.12.0.
- Added `error_handler` parameter in version 3.13.0 unreleased. Its default, `keep`, writes the bytes of a string or object key that is not valid UTF-8 unchanged, as before; `strict` (the default if [`JSON_STRICT_BINARY_UTF8`](https://json.nlohmann.me/api/macros/json_strict_binary_utf8/index.md) is enabled) throws `type_error.316`.
- Throws `type_error.321` for a discarded value since version 3.13.0 unreleased; previously, a discarded value nested in an array or object was silently skipped, producing invalid BJData.
