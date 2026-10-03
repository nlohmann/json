# nlohmann::basic_json::binary

```
// (1)
static basic_json binary(const typename binary_t::container_type& init);
static basic_json binary(typename binary_t::container_type&& init);

// (2)
static basic_json binary(const typename binary_t::container_type& init,
                         typename binary_t::subtype_type subtype);
static basic_json binary(typename binary_t::container_type&& init,
                         typename binary_t::subtype_type subtype);
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

## See also

- [binary_t](https://json.nlohmann.me/api/basic_json/binary_t/index.md) type for binary values
- [get_binary](https://json.nlohmann.me/api/basic_json/get_binary/index.md) get a reference to the stored binary value
- [is_binary](https://json.nlohmann.me/api/basic_json/is_binary/index.md) return whether the value is binary
- [byte_container_with_subtype](https://json.nlohmann.me/api/byte_container_with_subtype/index.md) container for binary values with subtype
- [Binary Values](https://json.nlohmann.me/features/binary_values/index.md) - the article on binary values

## Version history

- Added in version 3.8.0.
- Changed the type of `subtype` from `std::uint8_t` to `binary_t::subtype_type` (`std::uint64_t`) in version 3.10.0.
