# nlohmann::basic_json::error_handler_t

```
enum class error_handler_t {
    strict,
    replace,
    ignore
};
```

This enumeration is used in the [`dump`](https://json.nlohmann.me/api/basic_json/dump/index.md) function to choose how to treat decoding errors while serializing a `basic_json` value. Three values are differentiated:

strict : throw a `type_error` exception in case of invalid UTF-8

replace : replace invalid UTF-8 sequences with U+FFFD (� REPLACEMENT CHARACTER)

ignore : ignore invalid UTF-8 sequences; all valid bytes are copied to the output unchanged, and invalid bytes are dropped

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
              << '\n';
}
```

Output:

```
[json.exception.type_error.316] invalid UTF-8 byte at index 2: 0xA9
string with replaced invalid characters: "ä�ü"
string with ignored invalid characters: "äü"
```

## Version history

- Added in version 3.4.0.
