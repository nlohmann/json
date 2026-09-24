# <small>nlohmann::basic_json::</small>from_bjdata

```cpp
// (1)
template<typename InputType>
static basic_json from_bjdata(InputType&& i,
                              const bool strict = true,
                              const bool allow_exceptions = true);
// (2)
template<typename IteratorType, typename SentinelType = IteratorType>
static basic_json from_bjdata(IteratorType first, SentinelType last,
                              const bool strict = true,
                              const bool allow_exceptions = true);
```

Deserializes a given input to a JSON value using the BJData (Binary JData) serialization format.

1. Reads from a compatible input.
2. Reads from an iterator range, or an iterator and a sentinel of a different type (C++20 ranges support).

The exact mapping and its limitations are described on a [dedicated page](../../features/binary_formats/bjdata.md).

## Template parameters

`InputType`
:   A compatible input, for instance:

    - an `std::istream` object
    - a `FILE` pointer
    - a C-style array of characters
    - a pointer to a null-terminated string of single byte characters
    - a container `obj` for which `begin(obj)` and `end(obj)` produce a valid pair of iterators
      (as found via ADL or member functions, with semantics compatible to `std::begin` and `std::end`)

`IteratorType`
:   a compatible iterator type

`SentinelType`
:   defaults to `IteratorType`; may be a different type comparable to `IteratorType` via `operator!=`, for instance.

    - a custom sentinel type for C++20 ranges
    - `std::default_sentinel_t`, when `IteratorType` is `std::counted_iterator`

## Parameters

`i` (in)
:   an input in BJData format convertible to an input adapter

`first` (in)
:   iterator to the start of the input

`last` (in)
:   iterator to the end of the input, or a sentinel value that compares equal to the end iterator with `operator!=`

`strict` (in)
:   whether to expect the input to be consumed until EOF (`#!cpp true` by default)

`allow_exceptions` (in)
:   whether to throw exceptions in case of a parse error (optional, `#!cpp true` by default)

## Return value

deserialized JSON value; in case of a parse error and `allow_exceptions` set to `#!cpp false`, the return value will be
`value_t::discarded`. The latter can be checked with [`is_discarded`](is_discarded.md).

## Exception safety

Strong guarantee: if an exception is thrown, there are no changes in the JSON value.

## Exceptions

- Throws [parse_error.110](../../home/exceptions.md#jsonexceptionparse_error110) if the given input ends prematurely or
  the end of the file was not reached when `strict` was set to true
- Throws [parse_error.112](../../home/exceptions.md#jsonexceptionparse_error112) if a parse error occurs
- Throws [parse_error.113](../../home/exceptions.md#jsonexceptionparse_error113) if a string could not be parsed
  successfully
- Throws [out_of_range.408](../../home/exceptions.md#jsonexceptionout_of_range408) if the size of an optimized container
  or n-dimensional array cannot be represented by `std::size_t`

## Complexity

Linear in the size of the input.

## Examples

??? example

    The example shows the deserialization of a byte vector in BJData format to a JSON value.
     
    ```cpp
    --8<-- "examples/from_bjdata.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/from_bjdata.output"
    ```

## See also

- [to_bjdata](to_bjdata.md) create a BJData serialization of a JSON value
- [from_cbor](from_cbor.md) create a JSON value from an input in CBOR format
- [from_msgpack](from_msgpack.md) create a JSON value from an input in MessagePack format
- [from_bson](from_bson.md) create a JSON value from an input in BSON format
- [from_ubjson](from_ubjson.md) create a JSON value from an input in UBJSON format

## Version history

- Added in version 3.11.0.
- Extended container support (1) to include types with lvalue-only ADL `begin`/`end` (matching `std::begin`/`std::end` semantics) in version 3.13.0.
- Extended overload (2) to accept heterogeneous iterator+sentinel pairs (C++20 ranges support) in version 3.13.0.
