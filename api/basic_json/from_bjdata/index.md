# nlohmann::basic_json::from_bjdata

```
// (1)
template<typename InputType>
static basic_json from_bjdata(InputType&& i,
                              const bool strict = true,
                              const bool allow_exceptions = true);
// (2)
template<typename IteratorType>
static basic_json from_bjdata(IteratorType first, IteratorType last,
                              const bool strict = true,
                              const bool allow_exceptions = true);
```

Deserializes a given input to a JSON value using the BJData (Binary JData) serialization format.

1. Reads from a compatible input.
1. Reads from an iterator range.

The exact mapping and its limitations are described on a [dedicated page](https://json.nlohmann.me/features/binary_formats/bjdata/index.md).

## Template parameters

`InputType` : A compatible input, for instance:

```
- an `std::istream` object
- a `FILE` pointer
- a C-style array of characters
- a pointer to a null-terminated string of single byte characters
- an object `obj` for which `begin(obj)` and `end(obj)` produces a valid pair of iterators.
```

`IteratorType` : a compatible iterator type

## Parameters

`i` (in) : an input in BJData format convertible to an input adapter

`first` (in) : iterator to the start of the input

`last` (in) : iterator to the end of the input

`strict` (in) : whether to expect the input to be consumed until EOF (`true` by default)

`allow_exceptions` (in) : whether to throw exceptions in case of a parse error (optional, `true` by default)

## Return value

deserialized JSON value; in case of a parse error and `allow_exceptions` set to `false`, the return value will be `value_t::discarded`. The latter can be checked with [`is_discarded`](https://json.nlohmann.me/api/basic_json/is_discarded/index.md).

## Exception safety

Strong guarantee: if an exception is thrown, there are no changes in the JSON value.

## Exceptions

- Throws [parse_error.110](https://json.nlohmann.me/home/exceptions/#jsonexceptionparse_error110) if the given input ends prematurely or the end of the file was not reached when `strict` was set to true
- Throws [parse_error.112](https://json.nlohmann.me/home/exceptions/#jsonexceptionparse_error112) if a parse error occurs
- Throws [parse_error.113](https://json.nlohmann.me/home/exceptions/#jsonexceptionparse_error113) if a string could not be parsed successfully
- Throws [out_of_range.408](https://json.nlohmann.me/home/exceptions/#jsonexceptionout_of_range408) if the size of an optimized container or n-dimensional array cannot be represented by `std::size_t`

## Complexity

Linear in the size of the input.

## Examples

Example

The example shows the deserialization of a byte vector in BJData format to a JSON value.

```
#include <iostream>
#include <iomanip>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    // create byte vector
    std::vector<std::uint8_t> v = {0x7B, 0x69, 0x07, 0x63, 0x6F, 0x6D, 0x70, 0x61,
                                   0x63, 0x74, 0x54, 0x69, 0x06, 0x73, 0x63, 0x68,
                                   0x65, 0x6D, 0x61, 0x69, 0x00, 0x7D
                                  };

    // deserialize it with BJData
    json j = json::from_bjdata(v);

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

## See also

- [to_bjdata](https://json.nlohmann.me/api/basic_json/to_bjdata/index.md) create a BJData serialization of a JSON value
- [from_cbor](https://json.nlohmann.me/api/basic_json/from_cbor/index.md) create a JSON value from an input in CBOR format
- [from_msgpack](https://json.nlohmann.me/api/basic_json/from_msgpack/index.md) create a JSON value from an input in MessagePack format
- [from_bson](https://json.nlohmann.me/api/basic_json/from_bson/index.md) create a JSON value from an input in BSON format
- [from_ubjson](https://json.nlohmann.me/api/basic_json/from_ubjson/index.md) create a JSON value from an input in UBJSON format

## Version history

- Added in version 3.11.0.
