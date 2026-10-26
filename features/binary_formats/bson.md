# BSON

BSON, short for Binary JSON, is a binary-encoded serialization of JSON-like documents. Like JSON, BSON supports the
embedding of documents and arrays within other documents and arrays. BSON also contains extensions that allow
representation of data types that are not part of the JSON spec. For example, BSON has a Date type and a BinData type.

!!! abstract "References"

    - [BSON Website](http://bsonspec.org) - the main source on BSON
    - [BSON Specification](http://bsonspec.org/spec.html) - the specification
   

## Byte layout

A BSON document is a length-prefixed sequence of *elements*. The first four bytes hold the total size of the document (little-endian int32), followed by the elements, and a final `0x00` byte ends the document. Each element starts with a one-byte type, followed by its key as a NUL-terminated string and the value, whose encoding depends on the type. Arrays are documents whose keys are the decimal indices `"0"`, `"1"`, ...; nesting is expressed by embedding documents. Because every document announces its size, a reader can skip over it without parsing its content. The top level of a BSON value is always a document, which is why only JSON objects can be serialized.

Consider the following JSON value (shown formatted for readability):

```json
{
  "id": 300,
  "name": "json",
  "pi": 3.14,
  "tags": [
    "a",
    "b"
  ]
}
```

`to_bson` encodes it to 69 bytes (shown in hexadecimal; the encoding contains no whitespace). The colors mark the role of each byte: <span class="bl bl-t">type/marker</span> <span class="bl bl-l">length/count/size</span> <span class="bl bl-d">data</span>.

<div class="byte-layout" markdown="0"><table>
<thead><tr><th>JSON</th><th>Bytes</th><th>Meaning</th></tr></thead><tbody>
<tr><td><code>{</code></td><td><span class="bl bl-l">45 00 00 00</span></td><td>document size: 69 bytes (int32, little-endian)</td></tr>
<tr><td><code>&quot;id&quot;: 300,</code></td><td><span class="bl bl-t">10</span> <span class="bl bl-d">69 64 00</span> <span class="bl bl-d">2C 01 00 00</span></td><td>int32 element; key as NUL-terminated string; value (little-endian)</td></tr>
<tr><td><code>&quot;name&quot;: &quot;json&quot;,</code></td><td><span class="bl bl-t">02</span> <span class="bl bl-d">6E 61 6D 65 00</span> <span class="bl bl-l">05 00 00 00</span> <span class="bl bl-d">6A 73 6F 6E 00</span></td><td>string element; key; length incl. NUL (int32); NUL-terminated UTF-8 bytes</td></tr>
<tr><td><code>&quot;pi&quot;: 3.14,</code></td><td><span class="bl bl-t">01</span> <span class="bl bl-d">70 69 00</span> <span class="bl bl-d">1F 85 EB 51 B8 1E 09 40</span></td><td>double element; key; value (little-endian)</td></tr>
<tr><td><code>&quot;tags&quot;: [</code></td><td><span class="bl bl-t">04</span> <span class="bl bl-d">74 61 67 73 00</span> <span class="bl bl-l">17 00 00 00</span></td><td>array element; key; embedded document of 23 bytes (keys are the indices)</td></tr>
<tr><td><code>&quot;a&quot;,</code></td><td><span class="bl bl-t">02</span> <span class="bl bl-d">30 00</span> <span class="bl bl-l">02 00 00 00</span> <span class="bl bl-d">61 00</span></td><td>string element; key <code>&quot;0&quot;</code>; length 2; <code>a</code> + NUL</td></tr>
<tr><td><code>&quot;b&quot;</code></td><td><span class="bl bl-t">02</span> <span class="bl bl-d">31 00</span> <span class="bl bl-l">02 00 00 00</span> <span class="bl bl-d">62 00</span></td><td>string element; key <code>&quot;1&quot;</code>; length 2; <code>b</code> + NUL</td></tr>
<tr><td><code>]</code></td><td><span class="bl bl-t">00</span></td><td>end of the array document</td></tr>
<tr><td><code>}</code></td><td><span class="bl bl-t">00</span></td><td>end of the document</td></tr>
</tbody></table></div>

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
| number_unsigned | 9223372036854775808..18446744073709551615 | uint64    | 0x11   |
| number_float    | *any value*                               | double    | 0x01   |
| string          | *any value*                               | string    | 0x02   |
| array           | *any value*                               | document  | 0x04   |
| object          | *any value*                               | document  | 0x03   |
| binary          | *any value*                               | binary    | 0x05   |

!!! warning "Incomplete mapping"

    The mapping is **incomplete**, since only JSON-objects (and things contained therein) can be serialized to BSON.
    Also, keys may not contain U+0000, since they are serialized as zero-terminated C strings.

!!! info "Order of object members"

    The members of an object are written in the order in which iteration visits them: sorted by key for
    [`json`](../../api/json.md), in insertion order for [`ordered_json`](../../api/ordered_json.md).

!!! warning "BSON type 0x11 interoperability"

    The BSON specification defines type `0x11` as a Timestamp. This library uses marker `0x11` when serializing
    `number_unsigned` values in the range `9223372036854775808..18446744073709551615`. Other BSON implementations may
    therefore interpret these values as Timestamps instead of unsigned integers.

!!! info "Binary values without a subtype"

    BSON requires every binary value to have a subtype. If a binary value has no subtype, this library serializes it
    with the generic subtype `0x00`. After deserialization, `has_subtype()` returns `true` and `subtype()` returns `0`.
    As a result, serializing and deserializing a JSON object containing such a value produces a different JSON object,
    even though the binary data is unchanged.

!!! info "Binary subtype 0x02 (old binary)"

    The BSON specification defines the payload of the "binary (old)" subtype `0x02` as an int32 followed by that many
    bytes, so the value is preceded by two lengths: the length of the binary element and, as the first four bytes of
    the payload, the number of bytes that follow. A binary value with subtype `2` is therefore written with the outer
    length 4 bytes larger than its size and the size as inner length: `binary({1, 2, 3}, 2)` becomes
    `07 00 00 00 02 03 00 00 00 01 02 03`. When reading, the inner length is checked and removed, so the value
    contains only the bytes that follow it. `from_bson()` throws
    [`parse_error.112`](../../home/exceptions.md#jsonexceptionparse_error112) if the outer length is less than 4 or the
    inner length is not the outer length minus 4. Versions before 3.13.0 did not write the inner length and returned
    it as part of the payload; BSON data written by those versions with subtype 2 is not readable any more and must be
    written again.

??? example "Example: serialize a JSON value to BSON"

    ```cpp
    #include <iostream>
    #include <iomanip>
    #include <nlohmann/json.hpp>
    
    using nlohmann::json;
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
            std::cout << "0x" << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte) << " ";
        }
        std::cout << '\n';
    }
    
    ```
    
    Output:

    ```c
    0x1b 0x00 0x00 0x00 0x08 0x63 0x6f 0x6d 0x70 0x61 0x63 0x74 0x00 0x01 0x10 0x73 0x63 0x68 0x65 0x6d 0x61 0x00 0x00 0x00 0x00 0x00 0x00 
    
    ```

## Deserialization

The library maps BSON record types to JSON value types as follows:

| BSON type                | BSON marker byte | JSON value type |
|--------------------------|------------------|-----------------|
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

!!! warning "Incomplete mapping"

    The mapping is **incomplete**. The unsupported mappings are indicated in the table above.

!!! note "Handling of BSON type 0x11"

    This library deserializes BSON type `0x11` (Timestamp) as a `number_unsigned` value. The 64-bit value is preserved,
    but the Timestamp type information is not.

!!! warning "Lenient BSON input handling"

    The BSON reader is lenient in a few areas where the BSON specification is more restrictive:

    - array element keys are not checked against the required decimal sequence (`0`, `1`, `2`, ...),
    - any non-zero byte is accepted as `true` for the boolean type,
    - the payloads of the binary subtypes `0x03` (UUID, old), `0x04` (UUID), and `0x05` (MD5) are not checked to have
      16 bytes,
    - duplicate keys within a document are accepted; the last value wins (`{"a": 1, "a": 2}` is read as `{"a": 2}`),
      while a SAX handler receives every occurrence,
    - a `string` value may contain embedded `0x00` bytes, and
    - with `strict` set to `false`, bytes after the end of the document are ignored.

    If BSON input must be validated for strict specification compliance, validate it separately before passing it to
    `from_bson()`.

!!! note "Document size"

    Every document starts with its size. `from_bson()` rejects a document with
    [`parse_error.112`](../../home/exceptions.md#jsonexceptionparse_error112) if the size is less than 5 (the size prefix and the terminator), if an embedded document does not end before the
    end of the document that contains it, if the elements do not fit into the declared size, or if the size does not
    match the number of bytes read when the terminating `0x00` byte is reached. A size that is too small is detected
    before an element is read whose type byte and name no longer fit; an element that starts inside the declared size
    but extends past it is read, and reported to a SAX handler, before the mismatch is found at the terminator. A size
    that is too large is likewise found only at the terminator. Passing `strict` as `false` skips only the check for bytes after
    the end of the document ([`parse_error.110`](../../home/exceptions.md#jsonexceptionparse_error110)), not the
    document size checks.

!!! warning "Ill-formed UTF-8 in string values"

    The BSON specification requires `string` values (type `0x02`) to be valid UTF-8, but this is not required of a
    decoder, so checking is opt-in: with the [`error_handler`](../../api/basic_json/from_bson.md) parameter left at
    `keep` (the default), `from_bson()` accepts a `string` value whose bytes are not valid UTF-8 and hands them back
    unchanged. Passing `error_handler_t::strict` makes `from_bson()` check and throw
    [`parse_error.113`](../../home/exceptions.md#jsonexceptionparse_error113) for ill-formed UTF-8, and
    `replace`/`ignore` sanitize the string instead of keeping it. However, [`dump()`](../../api/basic_json/dump.md)
    still requires valid UTF-8 and throws [`type_error.316`](../../home/exceptions.md#jsonexceptiontype_error316) for a
    value read with the default `keep` handler, unless an error handler is passed that replaces or ignores the
    ill-formed bytes. `to_bson()`'s own `error_handler` parameter defaults to `keep`, so such a string value or element
    (key) name is written unchanged; with `strict` (the default if
    [`JSON_STRICT_BINARY_UTF8`](../../api/macros/json_strict_binary_utf8.md) is enabled), it throws the same exception
    instead. Element (key) names are treated like string values: with `keep` they are read unchanged, with `strict`,
    `replace`, or `ignore` they are checked and handled in the same way. `binary` values (type `0x05`) are unaffected,
    since they are not required to hold text.

??? example "Example: deserialize a JSON value from BSON"

    ```cpp
    #include <iostream>
    #include <iomanip>
    #include <nlohmann/json.hpp>
    
    using nlohmann::json;
    
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
        std::cout << std::setw(2) << j << '\n';
    }
    
    ```

    Output:

    ```json
    {
      "compact": true,
      "schema": 0
    }
    
    ```
