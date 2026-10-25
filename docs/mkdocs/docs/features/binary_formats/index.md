# Binary Formats

Though JSON is a ubiquitous data format, it is not a very compact format suitable for data exchange, for instance, over
a network. Hence, the library supports

- [BJData](bjdata.md) (Binary JData),
- [BON8](bon8.md) (Binary Object Notation 8),
- [BSON](bson.md) (Binary JSON),
- [CBOR](cbor.md) (Concise Binary Object Representation),
- [MessagePack](messagepack.md), and
- [UBJSON](ubjson.md) (Universal Binary JSON)

to efficiently encode JSON values to byte vectors and to decode such vectors.

## Comparison

### Completeness

| Format      | Serialization                                                          | Deserialization                                                       |
|-------------|------------------------------------------------------------------------|-----------------------------------------------------------------------|
| BJData      | complete                                                               | incomplete: no column-major ND-arrays, no Draft 4 SoA/extension types |
| BON8        | incomplete: no unsigned integers above int64, no invalid UTF-8 strings | complete                                                              |
| BSON        | incomplete: top-level value must be an object                          | incomplete, but all JSON types are supported                          |
| CBOR        | complete                                                               | incomplete, but all JSON types are supported                          |
| MessagePack | complete                                                               | incomplete, but all JSON types are supported                          |
| UBJSON      | complete                                                               | complete                                                              |

### Binary values

| Format      | Binary values            | Binary subtypes |
|-------------|--------------------------|-----------------|
| BJData      | supported (Draft 3 only) | not supported   |
| BON8        | not supported            | not supported   |
| BSON        | supported                | supported       |
| CBOR        | supported                | supported       |
| MessagePack | supported                | supported       |
| UBJSON      | not supported            | not supported   |

See [binary values](../binary_values.md) for more information.

### Sizes

| Format             | canada.json | twitter.json | citm_catalog.json | jeopardy.json |
|--------------------|-------------|--------------|-------------------|---------------|
| BJData             | 53.2 %      | 91.1 %       | 78.1 %            | 96.6 %        |
| BJData (size)      | 58.6 %      | 92.1 %       | 86.7 %            | 97.4 %        |
| BJData (size+type) | 58.6 %      | 92.1 %       | 86.5 %            | 97.4 %        |
| BON8               | **50.5 %**  | **83.8 %**   | **63.5 %**        | **87.5 %**    |
| BSON               | 85.8 %      | 95.2 %       | 95.8 %            | 106.7 %       |
| CBOR               | **50.5 %**  | 86.3 %       | 68.4 %            | 88.0 %        |
| MessagePack        | **50.5 %**  | 86.0 %       | 68.5 %            | 87.9 %        |
| UBJSON             | 53.2 %      | 91.3 %       | 78.2 %            | 96.6 %        |
| UBJSON (size)      | 58.6 %      | 92.3 %       | 86.8 %            | 97.4 %        |
| UBJSON (size+type) | 55.9 %      | 92.3 %       | 85.0 %            | 95.0 %        |

Sizes compared to minified JSON value; the smallest size per file is printed in bold.

## See also

- [Binary values](../binary_values.md) - binary values and subtypes
- [**to_cbor**](../../api/basic_json/to_cbor.md) / [**from_cbor**](../../api/basic_json/from_cbor.md), [**to_msgpack**](../../api/basic_json/to_msgpack.md) / [**from_msgpack**](../../api/basic_json/from_msgpack.md), [**to_bson**](../../api/basic_json/to_bson.md) / [**from_bson**](../../api/basic_json/from_bson.md), [**to_ubjson**](../../api/basic_json/to_ubjson.md) / [**from_ubjson**](../../api/basic_json/from_ubjson.md), [**to_bjdata**](../../api/basic_json/to_bjdata.md) / [**from_bjdata**](../../api/basic_json/from_bjdata.md), [**to_bon8**](../../api/basic_json/to_bon8.md) / [**from_bon8**](../../api/basic_json/from_bon8.md) - the conversion functions
- [Parsing untrusted input](../parsing/untrusted_input.md)
- [SAX interface](../parsing/sax_interface.md) - decode binary formats without building a value
