# Binary Formats

Though JSON is a ubiquitous data format, it is not a very compact format suitable for data exchange, for instance over
a network. Hence, the library supports

- [BJData](bjdata.md) (Binary JData),
- [BSON](bson.md) (Binary JSON),
- [CBOR](cbor.md) (Concise Binary Object Representation),
- [MessagePack](messagepack.md), and
- [UBJSON](ubjson.md) (Universal Binary JSON)
- BON8

to efficiently encode JSON values to byte vectors and to decode such vectors.

## Comparison

### Completeness

| Format      | Serialization                                 | Deserialization                              |
|-------------|-----------------------------------------------|----------------------------------------------|
| BJData      | complete                                      | complete                                     |
| BSON        | incomplete: top-level value must be an object | incomplete, but all JSON types are supported |
| CBOR        | complete                                      | incomplete, but all JSON types are supported |
| MessagePack | complete                                      | complete                                     |
| UBJSON      | complete                                      | complete                                     |
| BON8        | complete                                      | not yet implemented                          |

### Binary values

| Format      | Binary values | Binary subtypes |
|-------------|---------------|-----------------|
| BJData      | not supported | not supported   |
| BSON        | supported     | supported       |
| CBOR        | supported     | supported       |
| MessagePack | supported     | supported       |
| UBJSON      | not supported | not supported   |
| BON8        | not supported | not supported   |

See [binary values](../binary_values.md) for more information.

### Sizes

| Format             | [canada.json](https://github.com/nlohmann/json_test_data/blob/master/nativejson-benchmark/canada.json) | [twitter.json](https://github.com/nlohmann/json_test_data/blob/master/nativejson-benchmark/twitter.json) | [citm_catalog.json](https://github.com/nlohmann/json_test_data/blob/master/nativejson-benchmark/citm_catalog.json) | [jeopardy.json](https://github.com/nlohmann/json_test_data/blob/master/jeopardy/jeopardy.json) | [sample.json](https://github.com/nlohmann/json_test_data/blob/master/json_testsuite/sample.json) |
|--------------------|--------------------------------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------|
| BJData             | 53.2 %                                                                                                 | 91.1 %                                                                                                   | 78.1 %                                                                                                             | 96.6 %                                                                                         |
| BJData (size)      | 58.6 %                                                                                                 | 92.1 %                                                                                                   | 86.7 %                                                                                                             | 97.4 %                                                                                         |
| BJData (size+tyoe) | 58.6 %                                                                                                 | 92.1 %                                                                                                   | 86.5 %                                                                                                             | 97.4 %                                                                                         |
| BSON               | 85.8 %                                                                                                 | 95.2 %                                                                                                   | 95.8 %                                                                                                             | 106.7 % (1)                                                                                    | N/A (2)                                                                                          |
| CBOR               | 50.5 %                                                                                                 | 86.3 %                                                                                                   | 68.4 %                                                                                                             | 88.0 %                                                                                         | 87,2 %                                                                                           |
| MessagePack        | 50.5 %                                                                                                 | 86.0 %                                                                                                   | 68.5 %                                                                                                             | 87.9 %                                                                                         | 87,2 %                                                                                           |
| UBJSON             | 53.2 %                                                                                                 | 91.3 %                                                                                                   | 78.2 %                                                                                                             | 96.6 %                                                                                         | 88,2 %                                                                                           |
| UBJSON (size)      | 58.6 %                                                                                                 | 92.3 %                                                                                                   | 86.8 %                                                                                                             | 97.4 %                                                                                         | 89,3 %                                                                                           |
| UBJSON (size+type) | 55.9 %                                                                                                 | 92.3 %                                                                                                   | 85.0 %                                                                                                             | 95.0 %                                                                                         | 89,5 %                                                                                           |
| BON8               | 50,5 %                                                                                                 | 83,8 %                                                                                                   | 63,5 %                                                                                                             | 87,5 %                                                                                         | 85,6 %                                                                                           |

Sizes compared to minified JSON value.

Notes:

- (1) The JSON value is an array that needed to be wrapped in an object to be processed by BSON. We used an empty object key for minimal overhead.
- (2) The JSON value contained a string with code point `U+0000` which cannot be represented by BSON.

The JSON files are part of the [nlohmann/json_test_data](https://github.com/nlohmann/json_test_data) repository.
