# nlohmann::byte_container_with_subtype::byte_container_with_subtype

```
// (1)
byte_container_with_subtype();

// (2)
byte_container_with_subtype(const container_type& container);
byte_container_with_subtype(container_type&& container);

// (3)
byte_container_with_subtype(const container_type& container, subtype_type subtype);
byte_container_with_subtype(container_type&& container, subtype_type subtype);
```

1. Create an empty binary container without a subtype.
1. Create a binary container without a subtype.
1. Create a binary container with a subtype.

## Parameters

`container` (in) : binary container

`subtype` (in) : subtype

## Examples

Example

The example below demonstrates how byte containers can be created.

```
#include <iostream>
#include <nlohmann/json.hpp>

// define a byte container based on std::vector
using byte_container_with_subtype = nlohmann::byte_container_with_subtype<std::vector<std::uint8_t>>;

using json = nlohmann::json;

int main()
{
    // (1) create empty container
    auto c1 = byte_container_with_subtype();

    std::vector<std::uint8_t> bytes = {{0xca, 0xfe, 0xba, 0xbe}};

    // (2) create container
    auto c2 = byte_container_with_subtype(bytes);

    // (3) create container with subtype
    auto c3 = byte_container_with_subtype(bytes, 42);

    std::cout << json(c1) << "\n" << json(c2) << "\n" << json(c3) << std::endl;
}
```

Output:

```
{"bytes":[],"subtype":null}
{"bytes":[202,254,186,190],"subtype":null}
{"bytes":[202,254,186,190],"subtype":42}
```

## Version history

Since version 3.8.0.
