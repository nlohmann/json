# std::hash<nlohmann::basic_json>

```
namespace std {
    struct hash<nlohmann::basic_json>;
}
```

Return a hash value for a JSON object. The hash function tries to rely on `std::hash` where possible. Furthermore, the type of the JSON value is taken into account, so `null`, `false`, and numbers may hash differently from each other. Numbers that compare equal under [`operator==`](https://json.nlohmann.me/api/basic_json/operator_eq/index.md) always hash equally, regardless of whether they are stored as signed integer, unsigned integer, or floating-point number.

Numbers are hashed by their value converted to `number_float_t`. Converting an integer to `number_float_t` therefore keeps its hash, but converting a floating-point number to an integer type is lossy and can change it: `0.5` converts to `0`, which need not have the same hash. Unequal numbers can also share a hash value, for example two large integers that convert to the same `number_float_t`.

## Examples

Example

The example shows how to calculate hash values for different JSON values.

```
#include <iostream>
#include <iomanip>
#include <nlohmann/json.hpp>

using json = nlohmann::json;
using namespace nlohmann::literals;

int main()
{
    std::cout << "hash(null) = " << std::hash<json> {}(json(nullptr)) << '\n'
              << "hash(false) = " << std::hash<json> {}(json(false)) << '\n'
              << "hash(0) = " << std::hash<json> {}(json(0)) << '\n'
              << "hash(0U) = " << std::hash<json> {}(json(0U)) << '\n'
              << "hash(0.0) = " << std::hash<json> {}(json(0.0)) << '\n'
              << "hash(\"\") = " << std::hash<json> {}(json("")) << '\n'
              << "hash({}) = " << std::hash<json> {}(json::object()) << '\n'
              << "hash([]) = " << std::hash<json> {}(json::array()) << '\n'
              << "hash({\"hello\": \"world\"}) = " << std::hash<json> {}("{\"hello\": \"world\"}"_json)
              << std::endl;
}
```

Output:

```
hash(null) = 2654435769
hash(false) = 2654436030
hash(0) = 2654436221
hash(0U) = 2654436221
hash(0.0) = 2654436221
hash("") = 11160318156688833227
hash({}) = 2654435832
hash([]) = 2654435899
hash({"hello": "world"}) = 3701319991624763853
```

The hash values shown are examples only. They depend on the platform, the compiler, and the compiler version, and they can change between versions of this library. Do not persist them or rely on specific values.

## See also

- [operator==](https://json.nlohmann.me/api/basic_json/operator_eq/index.md) compares two JSON values for equality, consistent with equal hash values

## Version history

- Added in version 1.0.0.
- Extended for arbitrary basic_json types in version 3.10.5.
- Numbers that compare equal hash equally since version 3.13.0 unreleased; before, `0`, `0U`, and `0.0` had different hash values.
