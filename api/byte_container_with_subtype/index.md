# nlohmann::byte_container_with_subtype

```
template<typename BinaryType>
class byte_container_with_subtype : public BinaryType;
```

This type extends the template parameter `BinaryType` provided to [`basic_json`](https://json.nlohmann.me/api/basic_json/index.md) with a subtype used by BSON and MessagePack. This type exists so that the user does not have to specify a type themselves with a specific naming scheme in order to override the binary type.

## Template parameters

`BinaryType` : container to store bytes (`std::vector<std::uint8_t>` by default)

## Member types

- **container_type** - the type of the underlying container (`BinaryType`)
- **subtype_type** - the type of the subtype (`std::uint64_t`)

## Member functions

- [(constructor)](https://json.nlohmann.me/api/byte_container_with_subtype/byte_container_with_subtype/index.md)
- **operator==** - comparison: equal
- **operator!=** - comparison: not equal
- [**set_subtype**](https://json.nlohmann.me/api/byte_container_with_subtype/set_subtype/index.md) - sets the binary subtype
- [**subtype**](https://json.nlohmann.me/api/byte_container_with_subtype/subtype/index.md) - return the binary subtype
- [**has_subtype**](https://json.nlohmann.me/api/byte_container_with_subtype/has_subtype/index.md) - return whether the value has a subtype
- [**clear_subtype**](https://json.nlohmann.me/api/byte_container_with_subtype/clear_subtype/index.md) - clears the binary subtype

## Version history

- Added in version 3.8.0.
- Changed the type of subtypes to `std::uint64_t` in 3.10.0.
