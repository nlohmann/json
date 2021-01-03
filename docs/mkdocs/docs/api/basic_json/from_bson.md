# <small>nlohmann::basic_json::</small>from_bson

```cpp
// (1)
template<typename InputType>
static basic_json from_bson(InputType&& i,
                            const bool strict = true,
                            const bool allow_exceptions = true);
// (2)
template<typename IteratorType>
static basic_json from_bson(IteratorType first, IteratorType last,
                            const bool strict = true,
                            const bool allow_exceptions = true);
```

Deserializes a given input to a JSON value using the BSON (Binary JSON) serialization format.

1. Reads from a compatible input.
2. Reads from an iterator range.

The exact mapping and its limitations is described on a [dedicated page](../../features/binary_formats/bson.md).

## Template parameters

`InputType`
:   A compatible input, for instance:
    
    - an `std::istream` object
    - a `FILE` pointer
    - a C-style array of characters
    - a pointer to a null-terminated string of single byte characters
    - an object `obj` for which `begin(obj)` and `end(obj)` produces a valid pair of iterators.

`IteratorType`
:   a compatible iterator type

## Parameters

`i` (in)
:   an input in BSON format convertible to an input adapter

`first` (in)
:   iterator to start of the input

`last` (in)
:   iterator to end of the input

`strict` (in)
:   whether to expect the input to be consumed until EOF (`#!cpp true` by default)

`allow_exceptions` (in)
:   whether to throw exceptions in case of a parse error (optional, `#!cpp true` by default)

## Return value

deserialized JSON value; in case of a parse error and `allow_exceptions` set to `#!cpp false`, the return value will be
`value_t::discarded`.  The latter can be checked with [`is_discarded`](is_discarded.md).

## Exception safety

Strong guarantee: if an exception is thrown, there are no changes in the JSON value.

## Exceptions

Throws [`parse_error.114`](../../home/exceptions.md#jsonexceptionparse_error114) if an unsupported BSON record type is
encountered.

## Complexity

Linear in the size of the input.

## Examples

??? example

    The example shows the deserialization of a byte vector in BSON format to a JSON value.
     
    ```cpp
    --8<-- "examples/from_bson.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/from_bson.output"
    ```

## See also

- [BSON specification](http://bsonspec.org/spec.html)
- [to_bson](to_bson.md) for the analogous serialization
- [from_cbor](from_cbor.md) for the related CBOR format
- [from_msgpack](from_msgpack.md) for the related MessagePack format
- [from_ubjson](from_ubjson.md) for the related UBJSON format

## Version history

- Added in version 3.4.0.

!!! warning "Deprecation"

    - Overload (2) replaces calls to `from_bson` with a pointer and a length as first two parameters, which has been
      deprecated in version 3.8.0. This overload will be removed in version 4.0.0. Please replace all calls like
      `#!cpp from_bson(ptr, len, ...);` with `#!cpp from_bson(ptr, ptr+len, ...);`.
    - Overload (2) replaces calls to `from_bson` with a pair of iterators as their first parameter, which has been
      deprecated in version 3.8.0. This overload will be removed in version 4.0.0. Please replace all calls like
      `#!cpp from_bson({ptr, ptr+len}, ...);` with `#!cpp from_bson(ptr, ptr+len, ...);`.

    You should be warned by your compiler with a `-Wdeprecated-declarations` warning if you are using a deprecated
    function.
