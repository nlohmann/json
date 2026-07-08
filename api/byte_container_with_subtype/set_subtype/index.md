# nlohmann::byte_container_with_subtype::set_subtype

```
void set_subtype(subtype_type subtype) noexcept;
```

Sets the binary subtype of the value, also flags a binary JSON value as having a subtype, which has implications for serialization.

## Parameters

`subtype` (in) : subtype to set

## Exception safety

No-throw guarantee: this function never throws exceptions.

## Complexity

Constant.

## Examples

Example

The example below demonstrates how a subtype can be set with `set_subtype`.

```
#include <iostream>
#include <nlohmann/json.hpp>

// define a byte container based on std::vector
using byte_container_with_subtype = nlohmann::byte_container_with_subtype<std::vector<std::uint8_t>>;

using json = nlohmann::json;

int main()
{
    std::vector<std::uint8_t> bytes = {{0xca, 0xfe, 0xba, 0xbe}};

    // create container without subtype
    auto c = byte_container_with_subtype(bytes);

    std::cout << "before calling set_subtype(42): " << json(c) << '\n';

    // set the subtype
    c.set_subtype(42);

    std::cout << "after calling set_subtype(42): " << json(c) << '\n';
}
```

Output:

```
before calling set_subtype(42): {"bytes":[202,254,186,190],"subtype":null}
after calling set_subtype(42): {"bytes":[202,254,186,190],"subtype":42}
```

## Version history

Since version 3.8.0.
