# BSON

BSON, short for Binary JSON, is a binary-encoded serialization of JSON-like documents. Like JSON, BSON supports the embedding of documents and arrays within other documents and arrays. BSON also contains extensions that allow representation of data types that are not part of the JSON spec. For example, BSON has a Date type and a BinData type.

References

- [BSON Website](http://bsonspec.org) - the main source on BSON
- [BSON Specification](http://bsonspec.org/spec.html) - the specification

## Serialization

The library uses the following mapping from JSON values types to BSON types:

| JSON value type | value/range                               | BSON type | marker |
| --------------- | ----------------------------------------- | --------- | ------ |
| null            | `null`                                    | null      | 0x0A   |
| boolean         | `true`, `false`                           | boolean   | 0x08   |
| number_integer  | -9223372036854775808..-2147483649         | int64     | 0x12   |
| number_integer  | -2147483648..2147483647                   | int32     | 0x10   |
| number_integer  | 2147483648..9223372036854775807           | int64     | 0x12   |
| number_unsigned | 0..2147483647                             | int32     | 0x10   |
| number_unsigned | 2147483648..9223372036854775807           | int64     | 0x12   |
| number_unsigned | 9223372036854775808..18446744073709551615 | uint64    | 0x11   |
| number_float    | *any value*                               | double    | 0x01   |
| string          | *any value*                               | string    | 0x02   |
| array           | *any value*                               | document  | 0x04   |
| object          | *any value*                               | document  | 0x03   |
| binary          | *any value*                               | binary    | 0x05   |

Incomplete mapping

The mapping is **incomplete**, since only JSON-objects (and things contained therein) can be serialized to BSON. Also, keys may not contain U+0000, since they are serialized a zero-terminated c-strings.

BSON type 0x11 interoperability

The BSON specification defines type `0x11` as a Timestamp. This library uses marker `0x11` when serializing `number_unsigned` values in the range `9223372036854775808..18446744073709551615`. Other BSON implementations may therefore interpret these values as Timestamps instead of unsigned integers.

Binary values without a subtype

BSON requires every binary value to have a subtype. If a binary value has no subtype, this library serializes it with the generic subtype `0x00`. After deserialization, `has_subtype()` returns `true` and `subtype()` returns `0`. As a result, serializing and deserializing a JSON object containing such a value produces a different JSON object, even though the binary data is unchanged.

Example

```
#include <iostream>
#include <iomanip>
#include <nlohmann/json.hpp>

using json = nlohmann::json;
using namespace nlohmann::literals;

int main()
{
    // create a JSON value
    json j = R"({"compact": true, "schema": 0})"_json;

    // serialize it to BSON
    std::vector<std::uint8_t> v = json::to_bson(j);

    // print the vector content
    for (auto& byte : v)
    {
        std::cout << "0x" << std::hex << std::setw(2) << std::setfill('0') << (int)byte << " ";
    }
    std::cout << std::endl;
}
```

Output:

```
0x1b 0x00 0x00 0x00 0x08 0x63 0x6f 0x6d 0x70 0x61 0x63 0x74 0x00 0x01 0x10 0x73 0x63 0x68 0x65 0x6d 0x61 0x00 0x00 0x00 0x00 0x00 0x00
```

## Deserialization

The library maps BSON record types to JSON value types as follows:

| BSON type                | BSON marker byte | JSON value type |
| ------------------------ | ---------------- | --------------- |
| double                   | 0x01             | number_float    |
| string                   | 0x02             | string          |
| document                 | 0x03             | object          |
| array                    | 0x04             | array           |
| binary                   | 0x05             | binary          |
| undefined                | 0x06             | *unsupported*   |
| ObjectId                 | 0x07             | *unsupported*   |
| boolean                  | 0x08             | boolean         |
| UTC Date-Time            | 0x09             | *unsupported*   |
| null                     | 0x0A             | null            |
| Regular Expr.            | 0x0B             | *unsupported*   |
| DB Pointer               | 0x0C             | *unsupported*   |
| JavaScript Code          | 0x0D             | *unsupported*   |
| Symbol                   | 0x0E             | *unsupported*   |
| JavaScript Code w/ scope | 0x0F             | *unsupported*   |
| int32                    | 0x10             | number_integer  |
| uint64(Timestamp)        | 0x11             | number_unsigned |
| int64                    | 0x12             | number_integer  |
| 128-bit decimal float    | 0x13             | *unsupported*   |
| Max Key                  | 0x7F             | *unsupported*   |
| Min Key                  | 0xFF             | *unsupported*   |

Incomplete mapping

The mapping is **incomplete**. The unsupported mappings are indicated in the table above.

Handling of BSON type 0x11

This library deserializes BSON type `0x11` (Timestamp) as a `number_unsigned` value. The 64-bit value is preserved, but the Timestamp type information is not.

Example

```
#include <iostream>
#include <iomanip>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    // create byte vector
    std::vector<std::uint8_t> v = {0x1b, 0x00, 0x00, 0x00, 0x08, 0x63, 0x6f, 0x6d,
                                   0x70, 0x61, 0x63, 0x74, 0x00, 0x01, 0x10, 0x73,
                                   0x63, 0x68, 0x65, 0x6d, 0x61, 0x00, 0x00, 0x00,
                                   0x00, 0x00, 0x00
                                  };

    // deserialize it with BSON
    json j = json::from_bson(v);

    // print the deserialized JSON value
    std::cout << std::setw(2) << j << std::endl;
}
```

Output:

```
{
  "compact": true,
  "schema": 0
}
```
