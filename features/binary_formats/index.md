# Binary Formats

Though JSON is a ubiquitous data format, it is not a very compact format suitable for data exchange, for instance, over a network. Hence, the library supports

- [BJData](https://json.nlohmann.me/features/binary_formats/bjdata/index.md) (Binary JData),
- [BON8](https://json.nlohmann.me/features/binary_formats/bon8/index.md) (Binary Object Notation 8),
- [BSON](https://json.nlohmann.me/features/binary_formats/bson/index.md) (Binary JSON),
- [CBOR](https://json.nlohmann.me/features/binary_formats/cbor/index.md) (Concise Binary Object Representation),
- [MessagePack](https://json.nlohmann.me/features/binary_formats/messagepack/index.md), and
- [UBJSON](https://json.nlohmann.me/features/binary_formats/ubjson/index.md) (Universal Binary JSON)

to efficiently encode JSON values to byte vectors and to decode such vectors.

## Comparison

### Completeness

| Format      | Serialization                                 | Deserialization                                                       |
| ----------- | --------------------------------------------- | --------------------------------------------------------------------- |
| BJData      | complete                                      | incomplete: no column-major ND-arrays, no Draft 4 SoA/extension types |
| BON8        | incomplete: no unsigned integers above int64  | complete                                                              |
| BSON        | incomplete: top-level value must be an object | incomplete, but all JSON types are supported                          |
| CBOR        | complete                                      | incomplete, but all JSON types are supported                          |
| MessagePack | complete                                      | incomplete, but all JSON types are supported                          |
| UBJSON      | complete                                      | complete                                                              |

### Binary values

| Format      | Binary values            | Binary subtypes |
| ----------- | ------------------------ | --------------- |
| BJData      | supported (Draft 3 only) | not supported   |
| BON8        | not supported            | not supported   |
| BSON        | supported                | supported       |
| CBOR        | supported                | supported       |
| MessagePack | supported                | supported       |
| UBJSON      | not supported            | not supported   |

See [binary values](https://json.nlohmann.me/features/binary_values/index.md) for more information.

### Sizes

| Format             | canada.json | twitter.json | citm_catalog.json | jeopardy.json |
| ------------------ | ----------- | ------------ | ----------------- | ------------- |
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

- [Binary values](https://json.nlohmann.me/features/binary_values/index.md) - binary values and subtypes
- [**to_cbor**](https://json.nlohmann.me/api/basic_json/to_cbor/index.md) / [**from_cbor**](https://json.nlohmann.me/api/basic_json/from_cbor/index.md), [**to_msgpack**](https://json.nlohmann.me/api/basic_json/to_msgpack/index.md) / [**from_msgpack**](https://json.nlohmann.me/api/basic_json/from_msgpack/index.md), [**to_bson**](https://json.nlohmann.me/api/basic_json/to_bson/index.md) / [**from_bson**](https://json.nlohmann.me/api/basic_json/from_bson/index.md), [**to_ubjson**](https://json.nlohmann.me/api/basic_json/to_ubjson/index.md) / [**from_ubjson**](https://json.nlohmann.me/api/basic_json/from_ubjson/index.md), [**to_bjdata**](https://json.nlohmann.me/api/basic_json/to_bjdata/index.md) / [**from_bjdata**](https://json.nlohmann.me/api/basic_json/from_bjdata/index.md), [**to_bon8**](https://json.nlohmann.me/api/basic_json/to_bon8/index.md) / [**from_bon8**](https://json.nlohmann.me/api/basic_json/from_bon8/index.md) - the conversion functions
- [Parsing untrusted input](https://json.nlohmann.me/features/parsing/untrusted_input/index.md)
- [SAX interface](https://json.nlohmann.me/features/parsing/sax_interface/index.md) - decode binary formats without building a value
