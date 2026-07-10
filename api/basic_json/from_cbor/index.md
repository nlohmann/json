# nlohmann::basic_json::from_cbor

```
// (1)
template<typename InputType>
static basic_json from_cbor(InputType&& i,
                            const bool strict = true,
                            const bool allow_exceptions = true,
                            const cbor_tag_handler_t tag_handler = cbor_tag_handler_t::error);

// (2)
template<typename IteratorType>
static basic_json from_cbor(IteratorType first, IteratorType last,
                            const bool strict = true,
                            const bool allow_exceptions = true,
                            const cbor_tag_handler_t tag_handler = cbor_tag_handler_t::error);
```

Deserializes a given input to a JSON value using the CBOR (Concise Binary Object Representation) serialization format.

1. Reads from a compatible input.
1. Reads from an iterator range.

The exact mapping and its limitations are described on a [dedicated page](https://json.nlohmann.me/features/binary_formats/cbor/index.md).

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

`i` (in) : an input in CBOR format convertible to an input adapter

`first` (in) : iterator to the start of the input

`last` (in) : iterator to the end of the input

`strict` (in) : whether to expect the input to be consumed until EOF (`true` by default)

`allow_exceptions` (in) : whether to throw exceptions in case of a parse error (optional, `true` by default)

`tag_handler` (in) : how to treat CBOR tags (optional, `error` by default); see [`cbor_tag_handler_t`](https://json.nlohmann.me/api/basic_json/cbor_tag_handler_t/index.md) for more information

## Return value

deserialized JSON value; in case of a parse error and `allow_exceptions` set to `false`, the return value will be `value_t::discarded`. The latter can be checked with [`is_discarded`](https://json.nlohmann.me/api/basic_json/is_discarded/index.md).

## Exception safety

Strong guarantee: if an exception is thrown, there are no changes in the JSON value.

## Exceptions

- Throws [parse_error.110](https://json.nlohmann.me/home/exceptions/#jsonexceptionparse_error110) if the given input ends prematurely or the end of the file was not reached when `strict` was set to true
- Throws [parse_error.112](https://json.nlohmann.me/home/exceptions/#jsonexceptionparse_error112) if unsupported features from CBOR were used in the given input or if the input is not valid CBOR
- Throws [parse_error.113](https://json.nlohmann.me/home/exceptions/#jsonexceptionparse_error113) if a string was expected as a map key, but not found

## Complexity

Linear in the size of the input.

## Examples

Example

The example shows the deserialization of a byte vector in CBOR format to a JSON value.

```
#include <iostream>
#include <iomanip>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    // create byte vector
    std::vector<std::uint8_t> v = {0xa2, 0x67, 0x63, 0x6f, 0x6d, 0x70, 0x61, 0x63,
                                   0x74, 0xf5, 0x66, 0x73, 0x63, 0x68, 0x65, 0x6d,
                                   0x61, 0x00
                                  };

    // deserialize it with CBOR
    json j = json::from_cbor(v);

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

- [to_cbor](https://json.nlohmann.me/api/basic_json/to_cbor/index.md) create a CBOR serialization of a JSON value
- [from_msgpack](https://json.nlohmann.me/api/basic_json/from_msgpack/index.md) create a JSON value from an input in MessagePack format
- [from_bson](https://json.nlohmann.me/api/basic_json/from_bson/index.md) create a JSON value from an input in BSON format
- [from_ubjson](https://json.nlohmann.me/api/basic_json/from_ubjson/index.md) create a JSON value from an input in UBJSON format
- [from_bjdata](https://json.nlohmann.me/api/basic_json/from_bjdata/index.md) create a JSON value from an input in BJData format

## Version history

- Added in version 2.0.9.
- Parameter `start_index` since version 2.1.1.
- Changed to consume input adapters, removed `start_index` parameter, and added `strict` parameter in version 3.0.0.
- Added `allow_exceptions` parameter in version 3.2.0.
- Added `tag_handler` parameter in version 3.9.0.
- Extended container support (1) to include types with lvalue-only ADL `begin`/`end` (matching `std::begin`/`std::end` semantics) in version 3.13.0.

Deprecation

- Overload (2) replaces calls to `from_cbor` with a pointer and a length as first two parameters, which has been deprecated in version 3.8.0. This overload will be removed in version 4.0.0. Please replace all calls like `from_cbor(ptr, len, ...);` with `from_cbor(ptr, ptr+len, ...);`.
- Overload (2) replaces calls to `from_cbor` with a pair of iterators as their first parameter, which has been deprecated in version 3.8.0. This overload will be removed in version 4.0.0. Please replace all calls like `from_cbor({ptr, ptr+len}, ...);` with `from_cbor(ptr, ptr+len, ...);`.

You should be warned by your compiler with a `-Wdeprecated-declarations` warning if you are using a deprecated function.
