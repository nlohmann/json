# Overview

Though JSON is a ubiquitous data format, it is not a very compact format suitable for data exchange, for instance over a network. Hence, the library supports

- [BSON](bson.md) (Binary JSON),
- [CBOR](cbor.md) (Concise Binary Object Representation),
- [MessagePack](messagepack.md), and
- [UBJSON](ubjson.md) (Universal Binary JSON)

to efficiently encode JSON values to byte vectors and to decode such vectors.

## Comparison

### Completeness

| Format      | Serialization                                 | Deserialization                              |
| ----------- |---------------------------------------------- | -------------------------------------------- |
| BSON        | incomplete: top-level value must be an object | incomplete, but all JSON types are supported |
| CBOR        | complete                                      | incomplete, but all JSON types are supported |
| MessagePack | complete                                      | complete                                     |
| UBJSON      | complete                                      | complete                                     |

### Binary values

| Format      | Binary values | Binary subtypes |
| ----------- | ------------- | --------------- |
| BSON        | supported     | supported       |
| CBOR        | supported     | not supported   |
| MessagePack | supported     | supported       |
| UBJSON      | not supported | not supported   |

See [binary values](../binary_values.md) for more information.

### Sizes

| Format             | canada.json | twitter.json | citm_catalog.json | jeopardy.json |
| ------------------ | ----------- | ------------ | ----------------- | ------------- |
| BSON               | 85,8 %      | 95,2 %       | 95,8 %            | 106,7 %       |
| CBOR               | 50,5 %      | 86,3 %       | 68,4 %            | 88,0 %        |
| MessagePack        | 50,6 %      | 86,0 %       | 68,5 %            | 87,9 %        |
| UBJSON             | 53,2 %      | 91,3 %       | 78,2 %            | 96,6 %        |
| UBJSON (size)      | 58,6 %      | 92,3 %       | 86,8 %            | 97,4 %        |
| UBJSON (size+type) | 55,9 %      | 92,3 %       | 85,0 %            | 95,0 %        |

Sizes compared to minified JSON value.
