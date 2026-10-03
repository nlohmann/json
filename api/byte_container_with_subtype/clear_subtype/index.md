# nlohmann::byte_container_with_subtype::clear_subtype

```
void clear_subtype() noexcept;
```

Clears the binary subtype and flags the value as not having a subtype, which has implications for serialization; for instance, MessagePack will prefer the bin family over the ext family.

## Exception safety

No-throw guarantee: this function never throws exceptions.

## Complexity

Constant.

## Examples

Example

The example below demonstrates how `clear_subtype` can remove subtypes.

```
#include <iostream>
#include <nlohmann/json.hpp>

// define a byte container based on std::vector
using byte_container_with_subtype = nlohmann::byte_container_with_subtype<std::vector<std::uint8_t>>;

using json = nlohmann::json;

int main()
{
    std::vector<std::uint8_t> bytes = {{0xca, 0xfe, 0xba, 0xbe}};

    // create container with subtype
    auto c1 = byte_container_with_subtype(bytes, 42);

    std::cout << "before calling clear_subtype(): " << json(c1) << '\n';

    c1.clear_subtype();

    std::cout << "after calling clear_subtype(): " << json(c1) << '\n';
}
```

Output:

```
before calling clear_subtype(): {"bytes":[202,254,186,190],"subtype":42}
after calling clear_subtype(): {"bytes":[202,254,186,190],"subtype":null}
```

## See also

- [set_subtype](https://json.nlohmann.me/api/byte_container_with_subtype/set_subtype/index.md) sets the binary subtype
- [has_subtype](https://json.nlohmann.me/api/byte_container_with_subtype/has_subtype/index.md) return whether the value has a subtype
- [subtype](https://json.nlohmann.me/api/byte_container_with_subtype/subtype/index.md) return the binary subtype

## Version history

Since version 3.8.0.
