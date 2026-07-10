# nlohmann::basic_json::binary_t

```
using binary_t = byte_container_with_subtype<BinaryType>;
```

This type is a type designed to carry binary data that appears in various serialized formats, such as CBOR's Major Type 2, MessagePack's bin, and BSON's generic binary subtype. This type is NOT a part of standard JSON and exists solely for compatibility with these binary types. As such, it is simply defined as an ordered sequence of zero or more byte values.

Additionally, as an implementation detail, the subtype of the binary data is carried around as a `std::uint64_t`, which is compatible with both of the binary data formats that use binary subtyping, (though the specific numbering is incompatible with each other, and it is up to the user to translate between them). The subtype is added to `BinaryType` via the helper type [byte_container_with_subtype](https://json.nlohmann.me/api/byte_container_with_subtype/index.md).

[CBOR's RFC 7049](https://tools.ietf.org/html/rfc7049) describes this type as:

> Major type 2: a byte string. The string's length in bytes is represented following the rules for positive integers (major type 0).

[MessagePack's documentation on the bin type family](https://github.com/msgpack/msgpack/blob/master/spec.md#bin-format-family) describes this type as:

> Bin format family stores a byte array in 2, 3, or 5 bytes of extra bytes in addition to the size of the byte array.

[BSON's specifications](http://bsonspec.org/spec.html) describe several binary types; however, this type is intended to represent the generic binary type which has the description:

> Generic binary subtype - This is the most commonly used binary subtype and should be the 'default' for drivers and tools.

None of these impose any limitations on the internal representation other than the basic unit of storage be some type of array whose parts are decomposable into bytes.

The default representation of this binary format is a `std::vector<std::uint8_t>`, which is a very common way to represent a byte array in modern C++.

## Template parameters

`BinaryType` : container type to store arrays

```
Although not formally expressed as a C++ concept, `BinaryType` must be default-constructible,
copy/move-constructible, and support `push_back()`, `.data()`, and `.size()`, because
[`byte_container_with_subtype`](https://json.nlohmann.me/api/byte_container_with_subtype/index.md) derives directly from it. Its
`value_type` must additionally be exactly one byte wide (e.g., `std::uint8_t`/`char`/`std::byte`): the binary
serializers (CBOR, MessagePack, BSON, UBJSON) read and write the container's raw bytes via
`reinterpret_cast`, which is only correct for byte-sized elements -- a container like
`std::vector<std::intptr_t>` will not work as `BinaryType`.
```

## Notes

#### Default type

The default values for `BinaryType` is `std::vector<std::uint8_t>`.

#### Storage

Binary Arrays are stored as pointers in a `basic_json` type. That is, for any access to array values, a pointer of the type `binary_t*` must be dereferenced.

#### Notes on subtypes

- CBOR

  - Binary values are represented as byte strings. Subtypes are written as tags.

- MessagePack

  - If a subtype is given and the binary array contains exactly 1, 2, 4, 8, or 16 elements, the fixext family (fixext1, fixext2, fixext4, fixext8) is used. For other sizes, the ext family (ext8, ext16, ext32) is used. The subtype is then added as a signed 8-bit integer.
  - If no subtype is given, the bin family (bin8, bin16, bin32) is used.

- BSON

  - If a subtype is given, it is used and added as an unsigned 8-bit integer.
  - If no subtype is given, the generic binary subtype 0x00 is used.

## Examples

Example

The following code shows that `binary_t` is by default, a typedef to `nlohmann::byte_container_with_subtype<std::vector<std::uint8_t>>`.

```
#include <iostream>
#include <iomanip>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    std::cout << std::boolalpha << std::is_same<nlohmann::byte_container_with_subtype<std::vector<std::uint8_t>>, json::binary_t>::value << std::endl;
}
```

Output:

```
true
```

## See also

- [byte_container_with_subtype](https://json.nlohmann.me/api/byte_container_with_subtype/index.md)

## Version history

- Added in version 3.8.0. Changed the type of subtype to `std::uint64_t` in version 3.10.0.
