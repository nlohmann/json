# <small>nlohmann::</small>byte_container_with_subtype

```cpp
template<typename BinaryType>
class byte_container_with_subtype : public BinaryType;
```

This type extends the template parameter `BinaryType` provided to [`basic_json`](../basic_json/index.md) with a subtype
used by BSON, CBOR, and MessagePack. This type exists so that the user does not have to specify a type themselves with a
specific naming scheme in order to override the binary type.

## Template parameters

`BinaryType`
:   container to store bytes (`#!cpp std::vector<std::uint8_t>` by default)

## Member types

- **container_type** - the type of the underlying container (`BinaryType`)
- **subtype_type** - the type of the subtype (`#!cpp std::uint64_t`)

## Member functions

- [(constructor)](byte_container_with_subtype.md)
- [**operator==**](operator_eq.md) - comparison: equal
- [**operator!=**](operator_ne.md) - comparison: not equal
- [**set_subtype**](set_subtype.md) - sets the binary subtype
- [**subtype**](subtype.md) - return the binary subtype
- [**has_subtype**](has_subtype.md) - return whether the value has a subtype
- [**clear_subtype**](clear_subtype.md) - clears the binary subtype

## See also

- [Binary values](../../features/binary_values.md) - how binary values and subtypes are handled
- [`binary`](../basic_json/binary.md) - create a binary array value
- [`get_binary`](../basic_json/get_binary.md) - get a reference to the stored binary value
- [`binary_t`](../basic_json/binary_t.md) - type for binary arrays
- [Binary formats](../../features/binary_formats/index.md) - formats that can store binary values

## Version history

- Added in version 3.8.0.
- Changed the type of subtypes to `#!cpp std::uint64_t` in 3.10.0.
