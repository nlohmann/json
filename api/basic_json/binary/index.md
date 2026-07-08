# nlohmann::basic_json::binary

```
// (1)
static basic_json binary(const typename binary_t::container_type& init);
static basic_json binary(typename binary_t::container_type&& init);

// (2)
static basic_json binary(const typename binary_t::container_type& init,
                         std::uint8_t subtype);
static basic_json binary(typename binary_t::container_type&& init,
                         std::uint8_t subtype);
```

1. Creates a JSON binary array value from a given binary container.
1. Creates a JSON binary array value from a given binary container with subtype.

Binary values are part of various binary formats, such as CBOR, MessagePack, and BSON. This constructor is used to create a value for serialization to those formats.

## Parameters

`init` (in) : container containing bytes to use as a binary type

`subtype` (in) : subtype to use in CBOR, MessagePack, and BSON

## Return value

JSON binary array value

## Exception safety

Strong guarantee: if an exception is thrown, there are no changes in the JSON value.

## Complexity

Linear in the size of `init`; constant for `typename binary_t::container_type&& init` versions.

## Notes

Note, this function exists because of the difficulty in correctly specifying the correct template overload in the standard value ctor, as both JSON arrays and JSON binary arrays are backed with some form of a `std::vector`. Because JSON binary arrays are a non-standard extension, it was decided that it would be best to prevent automatic initialization of a binary array type, for backwards compatibility and so it does not happen on accident.

## Examples

Example

The following code shows how to create a binary value.

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

## Version history

- Added in version 3.8.0.
