# byte_container_with_subtype

```cpp
template<typename BinaryType>
class byte_container_with_subtype : public BinaryType
```

This type extends the template parameter `BinaryType` provided to [`basic_json`](basic_json/index.md) with a subtype
used by BSON and MessagePack. This type exists so that the user does not have to specify a type themselves with a
specific naming scheme in  order to override the binary type.

## Template parameters

`BinaryType`
:   container to store bytes (`#!cpp std::vector<std::uint8_t>` by default)

## Member types

- **container_type** - the type of the underlying container (`BinaryType`)
- **subtype_type** - the type of the subtype (`#!cpp std::uint64_t`)

## Member functions

- (constructor)
- (destructor)
- **operator==** - comparison: equal
- **operator!=** - comparison: not equal
- **set_subtype** - sets the binary subtype
- **subtype** - return the binary subtype
- **has_subtype** - return whether the value has a subtype
- **clear_subtype** - clears the binary subtype

## Version history

- Added in version 3.8.0.
- Changed type of subtypes to `#!cpp std::uint64_t` in 3.10.0.
