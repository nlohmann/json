# <small>nlohmann::basic_json::</small>to_bon8

```cpp
// (1)
static std::vector<std::uint8_t> to_bon8(const basic_json& j);

// (2)
static void to_bon8(const basic_json& j, detail::output_adapter<std::uint8_t> o);
static void to_bon8(const basic_json& j, detail::output_adapter<char> o);
```

Serializes a given JSON value `j` to a byte vector using the BON8 (Binary Object Notation 8) serialization format. BON8
is a compact binary serialization format that stores strings as UTF-8 without a length prefix.

1. Returns a byte vector containing the BON8 serialization.
2. Writes the BON8 serialization to an output adapter.

The exact mapping and its limitations are described on a [dedicated page](../../features/binary_formats/bon8.md).

## Parameters

`j` (in)
:   JSON value to serialize

`o` (in)
:   output adapter to write serialization to

## Return value

1. BON8 serialization as a byte vector
2. (none)

## Exception safety

Strong guarantee: if an exception is thrown, there are no changes in the JSON value `j`, which is never modified.
With (2), the bytes written before the exception remain in the output adapter.

## Exceptions

- Throws [out_of_range.407](../../home/exceptions.md#jsonexceptionout_of_range407) if `j` contains an unsigned integer
  above 9223372036854775807, which BON8 cannot represent
- Throws [type_error.316](../../home/exceptions.md#jsonexceptiontype_error316) if `j` contains a string that is not
  valid UTF-8
- Throws [type_error.321](../../home/exceptions.md#jsonexceptiontype_error321) if `j` or a value nested in it is
  discarded; example: `"cannot serialize discarded value to BON8"`

## Complexity

Linear in the size of the JSON value `j`.

## Examples

??? example "Example: serialize a JSON value to BON8"

    The example shows the serialization of a JSON value to a byte vector in BON8 format.
     
    ```cpp
    #include <iostream>
    #include <iomanip>
    #include <nlohmann/json.hpp>
    
    using json = nlohmann::json;
    using namespace nlohmann::literals;
    
    int main()
    {
        // create a JSON value
        json j = R"({"compact": true, "format": "BON8", "schema": 0})"_json;
    
        // serialize it to BON8
        std::vector<std::uint8_t> v = json::to_bon8(j);
    
        // print the vector content
        for (auto& byte : v)
        {
            std::cout << "0x" << std::hex << std::setw(2) << std::setfill('0') << (int)byte << " ";
        }
        std::cout << std::endl;
    }
    
    ```
    
    Output:
    
    ```json
    0x89 0x63 0x6f 0x6d 0x70 0x61 0x63 0x74 0xf9 0x66 0x6f 0x72 0x6d 0x61 0x74 0xff 0x42 0x4f 0x4e 0x38 0xff 0x73 0x63 0x68 0x65 0x6d 0x61 0x90 
    
    ```

??? example "Example: type_error.316 exception"

    The example shows how serializing a string that is not valid UTF-8 throws an exception, because BON8 stores strings
    as UTF-8.

    ```cpp
    #include <iostream>
    #include <nlohmann/json.hpp>
    
    using json = nlohmann::json;
    
    int main()
    {
        // create a JSON string that is not valid UTF-8
        std::string invalid_utf8;
        invalid_utf8.push_back(static_cast<char>(0xFF));
        json j = invalid_utf8;
    
        // exception type_error.316
        try
        {
            json::to_bon8(j);
        }
        catch (const json::type_error& e)
        {
            std::cout << e.what() << '\n';
        }
    }
    
    ```

    Output:

    ```json
    [json.exception.type_error.316] invalid UTF-8 byte at index 0: 0xFF
    
    ```

## See also

- [from_bon8](from_bon8.md) create a JSON value from an input in BON8 format
- [to_cbor](to_cbor.md) create a CBOR serialization of a JSON value
- [to_msgpack](to_msgpack.md) create a MessagePack serialization of a JSON value
- [to_bson](to_bson.md) create a BSON serialization of a JSON value
- [to_ubjson](to_ubjson.md) create a UBJSON serialization of a JSON value
- [to_bjdata](to_bjdata.md) create a BJData serialization of a JSON value

## Version history

- Added in version 3.13.0.
