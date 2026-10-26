# <small>nlohmann::basic_json::</small>to_ubjson

```cpp
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

Serializes a given JSON value `j` to a byte vector using the UBJSON (Universal Binary JSON) serialization format. UBJSON
aims to be more compact than JSON itself, yet more efficient to parse.

1. Returns a byte vector containing the UBJSON serialization.
2. Writes the UBJSON serialization to an output adapter.

The exact mapping and its limitations are described on a [dedicated page](../../features/binary_formats/ubjson.md).

## Parameters

`j` (in)
:   JSON value to serialize

`o` (in)
:   output adapter to write serialization to

`use_size` (in)
:   whether to add size annotations to container types; optional, `#!cpp false` by default.

`use_type` (in)
:   whether to add type annotations to container types (must be combined with `#!cpp use_size = true`); optional,
    `#!cpp false` by default.

`error_handler` (in)
:   how to treat a string or object key in `j` that is not valid UTF-8; see [`error_handler_t`](error_handler_t.md).
    The default, `keep`, writes the ill-formed bytes to the output as is, as every version of `to_ubjson` did before
    this parameter was added; `strict` throws; `replace`/`ignore` sanitize it the same way [`dump`](dump.md) would.
    If [`JSON_STRICT_BINARY_UTF8`](../macros/json_strict_binary_utf8.md) is enabled, the default is `strict` instead.

## Return value

1. UBJSON serialization as a byte vector
2. (none)

## Exception safety

Strong guarantee: if an exception is thrown, there are no changes in the JSON value.

## Exceptions

- Throws [`other_error.502`](../../home/exceptions.md#jsonexceptionother_error502) if `use_type` is true and `use_size`
  is false, and `j` contains a non-empty array, object, or binary value.
- Throws [type_error.316](../../home/exceptions.md#jsonexceptiontype_error316) if a string or object key in `j` is
  not valid UTF-8 and `error_handler` is `strict` (the default only if
  [`JSON_STRICT_BINARY_UTF8`](../macros/json_strict_binary_utf8.md) is enabled)
- Throws [type_error.321](../../home/exceptions.md#jsonexceptiontype_error321) if `j` or a value nested in it is
  discarded; example: `"cannot serialize discarded value to UBJSON"`

## Complexity

Linear in the size of the JSON value `j`.

## Examples

??? example "Example: serialize a JSON value to UBJSON"

    The example shows the serialization of a JSON value to a byte vector in UBJSON format.
     
    ```cpp
    #include <iostream>
    #include <iomanip>
    #include <nlohmann/json.hpp>
    
    using nlohmann::json;
    using namespace nlohmann::literals;
    
    // function to print UBJSON's diagnostic format
    void print_byte(uint8_t byte)
    {
        if (32 < byte and byte < 128)
        {
            std::cout << static_cast<char>(byte);
        }
        else
        {
            std::cout << static_cast<int>(byte);
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
        std::cout << '\n';
    
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
        std::cout << '\n';
    
        for (auto& byte : v_array_size)
        {
            print_byte(byte);
        }
        std::cout << '\n';
    
        for (auto& byte : v_array_size_and_type)
        {
            print_byte(byte);
        }
        std::cout << '\n';
    }
    
    ```
    
    Output:
    
    ```json
    {i7compactTi6schemaF}
    [i1i2i3i4i5i6i7i8]
    [#i8i1i2i3i4i5i6i7i8
    [$i#i812345678
    
    ```

??? example "Example: other_error.502 exception"

    The example shows how requesting type annotations (`use_type`) without size annotations (`use_size`) throws an
    exception, because type-optimized containers can only be read back with a preceding size.

    ```cpp
    #include <iostream>
    #include <nlohmann/json.hpp>
    
    using nlohmann::json;
    
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

    ```json
    [json.exception.other_error.502] use_type requires use_size = true
    
    ```

## See also

- [from_ubjson](from_ubjson.md) create a JSON value from an input in UBJSON format
- [to_cbor](to_cbor.md) create a CBOR serialization of a JSON value
- [to_msgpack](to_msgpack.md) create a MessagePack serialization of a JSON value
- [to_bson](to_bson.md) create a BSON serialization of a JSON value
- [to_bjdata](to_bjdata.md) create a BJData serialization of a JSON value
- [to_bon8](to_bon8.md) create a BON8 serialization of a JSON value

## Version history

- Added in version 3.1.0.
- Added `error_handler` parameter in version 3.13.0. Its default, `keep`, writes the bytes of a string or object key
  that is not valid UTF-8 unchanged, as before; `strict` (the default if
  [`JSON_STRICT_BINARY_UTF8`](../macros/json_strict_binary_utf8.md) is enabled) throws `type_error.316`.
- Throws `type_error.321` for a discarded value since version 3.13.0; previously, a discarded value nested in an
  array or object was silently skipped, producing invalid UBJSON.
