# basic_json::from_bson

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

The library maps BSON record types to JSON value types as follows:

BSON type       | BSON marker byte | JSON value type
--------------- | ---------------- | ---------------------------
double          | 0x01             | number_float
string          | 0x02             | string
document        | 0x03             | object
array           | 0x04             | array
binary          | 0x05             | binary
undefined       | 0x06             | still unsupported
ObjectId        | 0x07             | still unsupported
boolean         | 0x08             | boolean
UTC Date-Time   | 0x09             | still unsupported
null            | 0x0A             | null
Regular Expr.   | 0x0B             | still unsupported
DB Pointer      | 0x0C             | still unsupported
JavaScript Code | 0x0D             | still unsupported
Symbol          | 0x0E             | still unsupported
JavaScript Code | 0x0F             | still unsupported
int32           | 0x10             | number_integer
Timestamp       | 0x11             | still unsupported
128-bit decimal float | 0x13       | still unsupported
Max Key         | 0x7F             | still unsupported
Min Key         | 0xFF             | still unsupported

!!! warning

    The mapping is **incomplete**. The unsupported mappings are indicated in the table above.

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

## Exceptions

Throws [`parse_error.114`](../../home/exceptions.md#jsonexceptionparse_error114) if an unsupported BSON record type is
encountered.

## Exception safety

Strong guarantee: if an exception is thrown, there are no changes in the JSON value.

## Complexity

Linear in the size of the input.

## Example

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
- [to_cbor](to_cbor.md) for the related CBOR format
- [from_msgpack](from_msgpack.md) for the related MessagePack format
- [from_ubjson](from_ubjson.md) for the related UBJSON format

## Version history

- Added in version 3.4.0.
