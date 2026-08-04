# nlohmann::ordered_json

```
using ordered_json = basic_json<ordered_map>;
```

This type preserves the insertion order of object keys.

## Iterator invalidation

The type is based on [`ordered_map`](https://json.nlohmann.me/api/ordered_map/index.md) which in turn uses a `std::vector` to store object elements. Therefore, adding object elements can yield a reallocation in which case all iterators (including the [`end()`](https://json.nlohmann.me/api/basic_json/end/index.md) iterator) and all references to the elements are invalidated. Also, any iterator or reference after the insertion point will point to the same index, which is now a different value.

## Complexity

[`ordered_map`](https://json.nlohmann.me/api/ordered_map/index.md) has no lookup index: every key-based object operation is a linear scan, so building or parsing an object of `n` keys costs O(n²) rather than O(n log n). See [`ordered_map` complexity](https://json.nlohmann.me/api/ordered_map/#complexity) for the per-operation table and for measured numbers.

## Examples

Example

The example below demonstrates how `ordered_json` preserves the insertion order of object keys.

```
#include <iostream>
#include <nlohmann/json.hpp>

using ordered_json = nlohmann::ordered_json;

int main()
{
    ordered_json j;
    j["one"] = 1;
    j["two"] = 2;
    j["three"] = 3;

    std::cout << j.dump(2) << '\n';
}
```

Output:

```
{
  "one": 1,
  "two": 2,
  "three": 3
}
```

## See also

- [ordered_map](https://json.nlohmann.me/api/ordered_map/index.md)
- [Object Order](https://json.nlohmann.me/features/object_order/index.md)

## Version history

Since version 3.9.0.
