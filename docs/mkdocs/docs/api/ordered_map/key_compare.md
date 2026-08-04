# <small>nlohmann::ordered_map::</small>key_compare

```cpp
using key_compare = std::equal_to<Key>;  // until C++14

using key_compare = std::equal_to<>;     // since C++14
```

The comparator used to determine key equality when looking up elements. Unlike `std::map`, `ordered_map`
uses linear search with `key_compare` rather than an ordering relation, since element order reflects
insertion order rather than key order.

Since C++14, the transparent `#!cpp std::equal_to<>` is used, which enables heterogeneous lookup (e.g.
looking up by a `#!cpp const char*` key without constructing a temporary `Key`).

## Examples

??? example

    The example shows how `key_compare` is used.

    ```cpp
    --8<-- "examples/ordered_map__key_compare.cpp"
    ```

    Output:

    ```
    --8<-- "examples/ordered_map__key_compare.output"
    ```

## Version history

- Added in version 3.11.0.
