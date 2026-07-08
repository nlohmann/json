# std::hash<nlohmann::basic_json>

```
namespace std {
    struct hash<nlohmann::basic_json>;
}
```

Return a hash value for a JSON object. The hash function tries to rely on `std::hash` where possible. Furthermore, the type of the JSON value is taken into account to have different hash values for `null`, `0`, `0U`, and `false`, etc.

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
hash(0) = 2654436095
hash(0U) = 2654436156
hash("") = 6142509191626859748
hash({}) = 2654435832
hash([]) = 2654435899
hash({"hello": "world"}) = 4469488738203676328
```

Note the output is platform-dependent.

## Version history

- Added in version 1.0.0.
- Extended for arbitrary basic_json types in version 3.10.5.
