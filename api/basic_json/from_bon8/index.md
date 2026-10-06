# nlohmann::basic_json::from_bon8

```
// (1)
template<typename InputType>
static basic_json from_bon8(InputType&& i,
                            const bool strict = true,
                            const bool allow_exceptions = true);
// (2)
template<typename IteratorType, typename SentinelType = IteratorType>
static basic_json from_bon8(IteratorType first, SentinelType last,
                            const bool strict = true,
                            const bool allow_exceptions = true);
```

Deserializes a given input to a JSON value using the BON8 (Binary Object Notation 8) serialization format.

1. Reads from a compatible input.
1. Reads from an iterator range, or an iterator and a sentinel of a different type (C++20 ranges support).

The exact mapping and its limitations are described on a [dedicated page](https://json.nlohmann.me/features/binary_formats/bon8/index.md).

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

`i` (in) : an input in BON8 format convertible to an input adapter

`first` (in) : iterator to the start of the input

`last` (in) : iterator to the end of the input, or a sentinel value that compares equal to the end iterator with `operator!=`

`strict` (in) : whether to expect the input to be consumed until EOF (`true` by default)

`allow_exceptions` (in) : whether to throw exceptions in case of a parse error (optional, `true` by default)

## Return value

deserialized JSON value; in case of a parse error and `allow_exceptions` set to `false`, the return value will be `value_t::discarded`. The latter can be checked with [`is_discarded`](https://json.nlohmann.me/api/basic_json/is_discarded/index.md).

## Exception safety

Strong guarantee: if an exception is thrown, there are no changes in the JSON value.

## Exceptions

- Throws [parse_error.110](https://json.nlohmann.me/home/exceptions/#jsonexceptionparse_error110) if the given input ends prematurely or the end of the file was not reached when `strict` was set to true
- Throws [parse_error.112](https://json.nlohmann.me/home/exceptions/#jsonexceptionparse_error112) if a parse error occurs, for instance an invalid byte, a string that is not valid UTF-8, or an object key that is not a string

## Complexity

Linear in the size of the input.

## Examples

Example

The example shows the deserialization of a byte vector in BON8 format to a JSON value.

```
#include <iostream>
#include <iomanip>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    // create byte vector
    std::vector<std::uint8_t> v = {0x89, 0x63, 0x6f, 0x6d, 0x70, 0x61, 0x63, 0x74,
                                   0xf9, 0x66, 0x6f, 0x72, 0x6d, 0x61, 0x74, 0xff,
                                   0x42, 0x4f, 0x4e, 0x38, 0xff, 0x73, 0x63, 0x68,
                                   0x65, 0x6d, 0x61, 0x90
                                  };

    // deserialize it with BON8
    json j = json::from_bon8(v);

    // print the deserialized JSON value
    std::cout << std::setw(2) << j << std::endl;
}
```

Output:

```
{
  "compact": true,
  "format": "BON8",
  "schema": 0
}
```

## See also

- [to_bon8](https://json.nlohmann.me/api/basic_json/to_bon8/index.md) create a BON8 serialization of a JSON value
- [from_cbor](https://json.nlohmann.me/api/basic_json/from_cbor/index.md) create a JSON value from an input in CBOR format
- [from_msgpack](https://json.nlohmann.me/api/basic_json/from_msgpack/index.md) create a JSON value from an input in MessagePack format
- [from_bson](https://json.nlohmann.me/api/basic_json/from_bson/index.md) create a JSON value from an input in BSON format
- [from_ubjson](https://json.nlohmann.me/api/basic_json/from_ubjson/index.md) create a JSON value from an input in UBJSON format
- [from_bjdata](https://json.nlohmann.me/api/basic_json/from_bjdata/index.md) create a JSON value from an input in BJData format

## Version history

- Added in version 3.13.0 unreleased.

Deprecation

- Overload (2) replaces calls to `from_bon8` with a pointer and a length as first two parameters, which has been deprecated in version 3.13.0 unreleased. This overload will be removed in version 4.0.0. Please replace all calls like `from_bon8(ptr, len, ...);` with `from_bon8(ptr, ptr+len, ...);`.

You should be warned by your compiler with a `-Wdeprecated-declarations` warning if you are using a deprecated function.
