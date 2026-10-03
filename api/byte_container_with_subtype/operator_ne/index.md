# nlohmann::byte_container_with_subtype::operator!=

```
bool operator!=(const byte_container_with_subtype& rhs) const;
```

Compares two byte containers for inequality. Returns `!(rhs == *this)`; see [`operator==`](https://json.nlohmann.me/api/byte_container_with_subtype/operator_eq/index.md) for the equality semantics.

## Parameters

`rhs` (in) : byte container to compare `*this` with

## Return value

whether `*this` and `rhs` are not equal

## Complexity

Linear in the size of the compared containers.

## Examples

Example

The example below demonstrates comparing byte containers with and without subtypes.

```
#include <iostream>
#include <nlohmann/json.hpp>

// define a byte container based on std::vector
using byte_container_with_subtype = nlohmann::byte_container_with_subtype<std::vector<std::uint8_t>>;

int main()
{
    std::vector<std::uint8_t> bytes = {{0xca, 0xfe, 0xba, 0xbe}};

    // create containers without and with a subtype
    auto c1 = byte_container_with_subtype(bytes);
    auto c2 = byte_container_with_subtype(bytes);
    auto c3 = byte_container_with_subtype(bytes, 42);
    auto c4 = byte_container_with_subtype(bytes, 42);
    auto c5 = byte_container_with_subtype(bytes, 23);

    std::cout << std::boolalpha
              << "c1 != c2: " << (c1 != c2) << '\n'
              << "c1 != c3: " << (c1 != c3) << '\n'
              << "c3 != c4: " << (c3 != c4) << '\n'
              << "c3 != c5: " << (c3 != c5) << std::endl;
}
```

Output:

```
c1 != c2: false
c1 != c3: true
c3 != c4: false
c3 != c5: true
```

## See also

- [operator==](https://json.nlohmann.me/api/byte_container_with_subtype/operator_eq/index.md) comparison: equal
- [has_subtype](https://json.nlohmann.me/api/byte_container_with_subtype/has_subtype/index.md) return whether the value has a subtype
- [subtype](https://json.nlohmann.me/api/byte_container_with_subtype/subtype/index.md) return the binary subtype

## Version history

- Added in version 3.8.0.
