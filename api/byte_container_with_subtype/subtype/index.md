# nlohmann::byte_container_with_subtype::subtype

```
constexpr subtype_type subtype() const noexcept;
```

Returns the numerical subtype of the value if it has a subtype. If it does not have a subtype, this function will return `subtype_type(-1)` as a sentinel value.

## Return value

the numerical subtype of the binary value, or `subtype_type(-1)` if no subtype is set

## Exception safety

No-throw guarantee: this function never throws exceptions.

## Complexity

Constant.

## Examples

Example

The example below demonstrates how the subtype can be retrieved with `subtype`. Note how `subtype_type(-1)` is returned for container `c1`.

```
#include <iostream>
#include <nlohmann/json.hpp>

// define a byte container based on std::vector
using byte_container_with_subtype = nlohmann::byte_container_with_subtype<std::vector<std::uint8_t>>;

int main()
{
    std::vector<std::uint8_t> bytes = {{0xca, 0xfe, 0xba, 0xbe}};

    // create container
    auto c1 = byte_container_with_subtype(bytes);

    // create container with subtype
    auto c2 = byte_container_with_subtype(bytes, 42);

    std::cout << "c1.subtype() = " << c1.subtype()
              << "\nc2.subtype() = " << c2.subtype() << std::endl;

    // in case no subtype is set, return special value
    assert(c1.subtype() == static_cast<byte_container_with_subtype::subtype_type>(-1));
}
```

Output:

```
c1.subtype() = 18446744073709551615
c2.subtype() = 42
```

## Version history

- Added in version 3.8.0
- Fixed return value to properly return `subtype_type(-1)` as documented in version 3.10.0.
