# BSON

BSON, short for Binary JSON, is a binary-encoded serialization of JSON-like documents. Like JSON, BSON supports the
embedding of documents and arrays within other documents and arrays. BSON also contains extensions that allow
representation of data types that are not part of the JSON spec. For example, BSON has a Date type and a BinData type.

!!! abstract "References"

	- [BSON Website](http://bsonspec.org) - the main source on BSON
	- [BSON Specification](http://bsonspec.org/spec.html) - the specification
   

## Serialization

The library uses the following mapping from JSON values types to BSON types:

| JSON value type | value/range                               | BSON type | marker |
|-----------------|-------------------------------------------|-----------|--------|
| null            | `null`                                    | null      | 0x0A   |
| boolean         | `true`, `false`                           | boolean   | 0x08   |
| number_integer  | -9223372036854775808..-2147483649         | int64     | 0x12   |
| number_integer  | -2147483648..2147483647                   | int32     | 0x10   |
| number_integer  | 2147483648..9223372036854775807           | int64     | 0x12   |
| number_unsigned | 0..2147483647                             | int32     | 0x10   |
| number_unsigned | 2147483648..9223372036854775807           | int64     | 0x12   |
| number_unsigned | 9223372036854775808..18446744073709551615 | --        | --     |
| number_float    | *any value*                               | double    | 0x01   |
| string          | *any value*                               | string    | 0x02   |
| array           | *any value*                               | document  | 0x04   |
| object          | *any value*                               | document  | 0x03   |
| binary          | *any value*                               | binary    | 0x05   |

!!! warning "Incomplete mapping"

    The mapping is **incomplete**, since only JSON-objects (and things
    contained therein) can be serialized to BSON.
    Also, integers larger than 9223372036854775807 cannot be serialized to BSON,
    and the keys may not contain U+0000, since they are serialized a
    zero-terminated c-strings.

??? example

    ```cpp
    --8<-- "examples/to_bson.cpp"
    ```
    
    Output:

    ```c
    --8<-- "examples/to_bson.output"
    ```


## Deserialization

The library maps BSON record types to JSON value types as follows:

| BSON type             | BSON marker byte | JSON value type |
|-----------------------|------------------|-----------------|
| double                | 0x01             | number_float    |
| string                | 0x02             | string          |
| document              | 0x03             | object          |
| array                 | 0x04             | array           |
| binary                | 0x05             | binary          |
| undefined             | 0x06             | *unsupported*   |
| ObjectId              | 0x07             | *unsupported*   |
| boolean               | 0x08             | boolean         |
| UTC Date-Time         | 0x09             | *unsupported*   |
| null                  | 0x0A             | null            |
| Regular Expr.         | 0x0B             | *unsupported*   |
| DB Pointer            | 0x0C             | *unsupported*   |
| JavaScript Code       | 0x0D             | *unsupported*   |
| Symbol                | 0x0E             | *unsupported*   |
| JavaScript Code       | 0x0F             | *unsupported*   |
| int32                 | 0x10             | number_integer  |
| Timestamp             | 0x11             | *unsupported*   |
| 128-bit decimal float | 0x13             | *unsupported*   |
| Max Key               | 0x7F             | *unsupported*   |
| Min Key               | 0xFF             | *unsupported*   |

!!! warning "Incomplete mapping"

    The mapping is **incomplete**. The unsupported mappings are indicated in the table above.


??? example

    ```cpp
    --8<-- "examples/from_bson.cpp"
    ```

    Output:

    ```json
    --8<-- "examples/from_bson.output"
    ```
