# nlohmann::basic_json::get_binary

```
binary_t& get_binary();

const binary_t& get_binary() const;
```

Returns a reference to the stored binary value.

## Return value

Reference to binary value.

## Exception safety

Strong exception safety: if an exception occurs, the original value stays intact.

## Exceptions

Throws [`type_error.302`](https://json.nlohmann.me/home/exceptions/#jsonexceptiontype_error302) if the value is not binary

## Complexity

Constant.

## Examples

Example

The following code shows how to query a binary value.

```
#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    // create a binary vector
    std::vector<std::uint8_t> vec = {0xCA, 0xFE, 0xBA, 0xBE};

    // create a binary JSON value with subtype 42
    json j = json::binary(vec, 42);

    // output type and subtype
    std::cout << "type: " << j.type_name() << ", subtype: " << j.get_binary().subtype() << std::endl;
}
```

Output:

```
type: binary, subtype: 42
```

## See also

- [get](https://json.nlohmann.me/api/basic_json/get/index.md) get a value (explicit conversion)
- [get_ref](https://json.nlohmann.me/api/basic_json/get_ref/index.md) get a reference to the stored value

## Version history

- Added in version 3.8.0.
