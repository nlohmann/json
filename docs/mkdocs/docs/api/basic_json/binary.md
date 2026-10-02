# <small>nlohmann::basic_json::</small>binary

```cpp
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
2. Creates a JSON binary array value from a given binary container with subtype.
 
Binary values are part of various binary formats, such as CBOR, MessagePack, and BSON. This constructor is used to
create a value for serialization to those formats.

## Parameters

`init` (in)
:   container containing bytes to use as a binary type

`subtype` (in)
:   subtype to use in CBOR, MessagePack, and BSON

## Return value

JSON binary array value

## Exception safety

Strong guarantee: if an exception is thrown, there are no changes in the JSON value.

## Complexity

Linear in the size of `init`; constant for `typename binary_t::container_type&& init` versions.

## Notes

Note, this function exists because of the difficulty in correctly specifying the correct template overload in the
standard value ctor, as both JSON arrays and JSON binary arrays are backed with some form of a `std::vector`. Because
JSON binary arrays are a non-standard extension, it was decided that it would be best to prevent automatic
initialization of a binary array type, for backwards compatibility and so it does not happen on accident.

## Examples

??? example

    The following code shows how to create a binary value.
     
    ```cpp
    --8<-- "examples/binary.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/binary.output"
    ```

## See also

- [binary_t](binary_t.md) type for binary values
- [get_binary](get_binary.md) get a reference to the stored binary value
- [is_binary](is_binary.md) return whether the value is binary
- [byte_container_with_subtype](../byte_container_with_subtype/index.md) container for binary values with subtype
- [Binary Values](../../features/binary_values.md) - the article on binary values

## Version history

- Added in version 3.8.0.
- Changed the type of `subtype` from `std::uint8_t` to `binary_t::subtype_type` (`std::uint64_t`) in version 3.10.0.
