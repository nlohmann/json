# nlohmann::basic_json::from_bson

```
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
1. Reads from an iterator range.

The exact mapping and its limitations are described on a [dedicated page](https://json.nlohmann.me/features/binary_formats/bson/index.md).

## Template parameters

`InputType` : A compatible input, for instance:

```
- an `std::istream` object
- a `FILE` pointer
- a C-style array of characters
- a pointer to a null-terminated string of single byte characters
- a container `obj` for which `begin(obj)` and `end(obj)` produce a valid pair of iterators
  (as found via ADL or member functions, with semantics compatible to `std::begin` and `std::end`)
```

`IteratorType` : a compatible iterator type

## Parameters

`i` (in) : an input in BSON format convertible to an input adapter

`first` (in) : iterator to the start of the input

`last` (in) : iterator to the end of the input

`strict` (in) : whether to expect the input to be consumed until EOF (`true` by default)

`allow_exceptions` (in) : whether to throw exceptions in case of a parse error (optional, `true` by default)

## Return value

deserialized JSON value; in case of a parse error and `allow_exceptions` set to `false`, the return value will be `value_t::discarded`. The latter can be checked with [`is_discarded`](https://json.nlohmann.me/api/basic_json/is_discarded/index.md).

## Exception safety

Strong guarantee: if an exception is thrown, there are no changes in the JSON value.

## Exceptions

- Throws [`parse_error.110`](https://json.nlohmann.me/home/exceptions/#jsonexceptionparse_error110) if the given input ends prematurely or the end of the input was not reached when `strict` was set to true
- Throws [`parse_error.112`](https://json.nlohmann.me/home/exceptions/#jsonexceptionparse_error112) if a parse error occurs (e.g., an invalid string or byte array length)
- Throws [`parse_error.114`](https://json.nlohmann.me/home/exceptions/#jsonexceptionparse_error114) if an unsupported BSON record type is encountered

## Complexity

Linear in the size of the input.

## Examples

Example

The example shows the deserialization of a byte vector in BSON format to a JSON value.

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

## See also

- [BSON specification](http://bsonspec.org/spec.html)
- [to_bson](https://json.nlohmann.me/api/basic_json/to_bson/index.md) for the analogous serialization
- [from_cbor](https://json.nlohmann.me/api/basic_json/from_cbor/index.md) for the related CBOR format
- [from_msgpack](https://json.nlohmann.me/api/basic_json/from_msgpack/index.md) for the related MessagePack format
- [from_ubjson](https://json.nlohmann.me/api/basic_json/from_ubjson/index.md) for the related UBJSON format
- [from_bjdata](https://json.nlohmann.me/api/basic_json/from_bjdata/index.md) for the related BJData format

## Version history

- Added in version 3.4.0.
- Extended container support (1) to include types with lvalue-only ADL `begin`/`end` (matching `std::begin`/`std::end` semantics) in version 3.13.0.

Deprecation

- Overload (2) replaces calls to `from_bson` with a pointer and a length as first two parameters, which has been deprecated in version 3.8.0. This overload will be removed in version 4.0.0. Please replace all calls like `from_bson(ptr, len, ...);` with `from_bson(ptr, ptr+len, ...);`.
- Overload (2) replaces calls to `from_bson` with a pair of iterators as their first parameter, which has been deprecated in version 3.8.0. This overload will be removed in version 4.0.0. Please replace all calls like `from_bson({ptr, ptr+len}, ...);` with `from_bson(ptr, ptr+len, ...);`.

You should be warned by your compiler with a `-Wdeprecated-declarations` warning if you are using a deprecated function.
