# nlohmann::basic_json::from_ubjson

```
// (1)
template<typename InputType>
static basic_json from_ubjson(InputType&& i,
                              const bool strict = true,
                              const bool allow_exceptions = true,
                              const error_handler_t error_handler = error_handler_t::keep);
// (2)
template<typename IteratorType, typename SentinelType = IteratorType>
static basic_json from_ubjson(IteratorType first, SentinelType last,
                              const bool strict = true,
                              const bool allow_exceptions = true,
                              const error_handler_t error_handler = error_handler_t::keep);
```

Deserializes a given input to a JSON value using the UBJSON (Universal Binary JSON) serialization format.

1. Reads from a compatible input.
1. Reads from an iterator range, or an iterator and a sentinel of a different type (C++20 ranges support).

The exact mapping and its limitations are described on a [dedicated page](https://json.nlohmann.me/features/binary_formats/ubjson/index.md).

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

`SentinelType` : defaults to `IteratorType`; may be a different type comparable to `IteratorType` via `operator!=`, for instance.

```
- a custom sentinel type for C++20 ranges
- `std::default_sentinel_t`, when `IteratorType` is `std::counted_iterator`
```

## Parameters

`i` (in) : an input in UBJSON format convertible to an input adapter

`first` (in) : iterator to the start of the input

`last` (in) : iterator to the end of the input, or a sentinel value that compares equal to the end iterator with `operator!=`

`strict` (in) : whether to expect the input to be consumed until EOF (`true` by default)

`allow_exceptions` (in) : whether to throw exceptions in case of a parse error (optional, `true` by default)

`error_handler` (in) : how to treat a string value or object key that is not valid UTF-8; see [`error_handler_t`](https://json.nlohmann.me/api/basic_json/error_handler_t/index.md). UBJSON does not require a decoder to reject ill-formed UTF-8, so checking is opt-in: the default, `keep`, does not check at all, as every binary reader did before this parameter was added; `strict` checks and throws; `replace`/`ignore` sanitize the string the same way [`dump`](https://json.nlohmann.me/api/basic_json/dump/index.md) would

## Return value

deserialized JSON value; in case of a parse error and `allow_exceptions` set to `false`, the return value will be `value_t::discarded`. The latter can be checked with [`is_discarded`](https://json.nlohmann.me/api/basic_json/is_discarded/index.md).

## Exception safety

Strong guarantee: if an exception is thrown, there are no changes in the JSON value.

## Exceptions

- Throws [parse_error.110](https://json.nlohmann.me/home/exceptions/#jsonexceptionparse_error110) if the given input ends prematurely or the end of the file was not reached when `strict` was set to true
- Throws [parse_error.112](https://json.nlohmann.me/home/exceptions/#jsonexceptionparse_error112) if an invalid type marker is read (including a type marker after `$` of an optimized container, even if its count is 0), or if `$` is not followed by `#`
- Throws [parse_error.113](https://json.nlohmann.me/home/exceptions/#jsonexceptionparse_error113) if a string could not be parsed successfully (negative or non-integer length, `C` followed by a byte above 0x7F), if the count of an optimized container is negative, or if a string value or object key is not valid UTF-8 and `error_handler` is `strict`
- Throws [parse_error.115](https://json.nlohmann.me/home/exceptions/#jsonexceptionparse_error115) if the text of a high-precision number (`H`) is not a valid JSON number
- Throws [out_of_range.406](https://json.nlohmann.me/home/exceptions/#jsonexceptionout_of_range406) if a high-precision number, or a float64 when `number_float_t` is `float`, does not fit into `number_float_t`
- Throws [out_of_range.408](https://json.nlohmann.me/home/exceptions/#jsonexceptionout_of_range408) if the count of an optimized container exceeds the capacity of the container (or of `std::size_t`), or if an optimized array of `Z`, `T`, or `F` has more than 1,048,576 elements

## Complexity

Linear in the size of the input.

## Examples

Example

The example shows the deserialization of a byte vector in UBJSON format to a JSON value.

```
#include <iostream>
#include <iomanip>
#include <nlohmann/json.hpp>

using nlohmann::json;

int main()
{
    // create byte vector
    std::vector<std::uint8_t> v = {0x7B, 0x69, 0x07, 0x63, 0x6F, 0x6D, 0x70, 0x61,
                                   0x63, 0x74, 0x54, 0x69, 0x06, 0x73, 0x63, 0x68,
                                   0x65, 0x6D, 0x61, 0x69, 0x00, 0x7D
                                  };

    // deserialize it with UBJSON
    json j = json::from_ubjson(v);

    // print the deserialized JSON value
    std::cout << std::setw(2) << j << '\n';
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

- [UBJSON](https://json.nlohmann.me/features/binary_formats/ubjson/index.md) - the format, its byte layout and how values are mapped
- [Binary formats](https://json.nlohmann.me/features/binary_formats/index.md) - overview and comparison of the supported binary formats
- [Parsing untrusted input](https://json.nlohmann.me/features/parsing/untrusted_input/index.md) - limits and safe handling of hostile data
- [Binary values](https://json.nlohmann.me/features/binary_values/index.md) - how binary values and subtypes are handled
- [`to_ubjson`](https://json.nlohmann.me/api/basic_json/to_ubjson/index.md) - create a UBJSON serialization of a JSON value
- [`from_cbor`](https://json.nlohmann.me/api/basic_json/from_cbor/index.md) - create a JSON value from an input in CBOR format
- [`from_msgpack`](https://json.nlohmann.me/api/basic_json/from_msgpack/index.md) - create a JSON value from an input in MessagePack format
- [`from_bson`](https://json.nlohmann.me/api/basic_json/from_bson/index.md) - create a JSON value from an input in BSON format
- [`from_bjdata`](https://json.nlohmann.me/api/basic_json/from_bjdata/index.md) - create a JSON value from an input in BJData format
- [`from_bon8`](https://json.nlohmann.me/api/basic_json/from_bon8/index.md) - create a JSON value from an input in BON8 format

## Version history

- Added in version 3.1.0.
- Added `allow_exceptions` parameter in version 3.2.0.
- Extended container support (1) to include types with lvalue-only ADL `begin`/`end` (matching `std::begin`/`std::end` semantics) in version 3.13.0 unreleased.
- Extended overload (2) to accept heterogeneous iterator+sentinel pairs (C++20 ranges support) in version 3.13.0 unreleased.
- Added `error_handler` parameter in version 3.13.0 unreleased.

Deprecation

- Overload (2) replaces calls to `from_ubjson` with a pointer and a length as first two parameters, which has been deprecated in version 3.8.0. In version 4.0.0 unreleased, this overload will be deleted (`= delete`) rather than removed. Please replace all calls like `from_ubjson(ptr, len, ...);` with `from_ubjson(ptr, ptr+len, ...);`.
- Overload (2) replaces calls to `from_ubjson` with a pair of iterators as their first parameter, which has been deprecated in version 3.8.0. This overload will be removed in version 4.0.0. Please replace all calls like `from_ubjson({ptr, ptr+len}, ...);` with `from_ubjson(ptr, ptr+len, ...);`.

You should be warned by your compiler with a `-Wdeprecated-declarations` warning if you are using a deprecated function.

See the [migration guide](https://json.nlohmann.me/integration/migration_guide/#parsing) for how to update existing code.
