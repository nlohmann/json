# <small>nlohmann::basic_json::</small>cbor_tag_handler_t

```cpp
enum class cbor_tag_handler_t
{
    error,
    ignore,
    store
};
```

This enumeration is used in [`from_cbor`](from_cbor.md) and [`sax_parse`](sax_parse.md) to choose how to treat tags:

error
:   report a parse error in case of a tag (the `from_cbor` overloads throw a `parse_error` exception by default)

ignore
:   ignore tags (also in front of a text string map key)

store
:   store tagged byte strings (for bytes 0xd8..0xdb) as binary values with the tag as subtype; other tagged values are
    read as if the tag were ignored. If several tags precede a byte string, only the tag directly in front of it is
    stored, and only when it has the form 0xd8..0xdb (a tag 0..23 written as 0xc0..0xd7 is skipped). Tags in front of a
    text string map key are skipped.

## Examples

??? example

    The example below shows how the different values of the `cbor_tag_handler_t` influence the behavior of
    [`from_cbor`](from_cbor.md) when reading a tagged byte string.

    ```cpp
    #include <iostream>
    #include <nlohmann/json.hpp>
    
    using nlohmann::json;
    
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
            std::cout << e.what() << '\n';
        }
    
        // cbor_tag_handler_t::ignore ignores the tag
        auto b_ignore_tag = json::from_cbor(vec, true, true, json::cbor_tag_handler_t::ignore);
        std::cout << b_ignore_tag << '\n';
    
        // cbor_tag_handler_t::store stores the tag as binary subtype
        auto b_store_tag = json::from_cbor(vec, true, true, json::cbor_tag_handler_t::store);
        std::cout << b_store_tag << '\n';
    }
    
    ```
    
    Output:
    
    ```json
    [json.exception.parse_error.112] parse error at byte 1: syntax error while parsing CBOR value: invalid byte: 0xD8
    {"bytes":[202,254,186,190],"subtype":null}
    {"bytes":[202,254,186,190],"subtype":66}
    
    ```

## See also

- [from_cbor](from_cbor.md) deserializes a JSON value from CBOR
- [input_format_t](input_format_t.md) the enumeration of supported input formats
- [CBOR](../../features/binary_formats/cbor.md) - the article on the CBOR format

## Version history

- Added in version 3.9.0. Added value `store` in 3.10.0.
