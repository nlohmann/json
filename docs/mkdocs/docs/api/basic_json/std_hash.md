# <small>std::</small>hash<nlohmann::basic_json\>

```cpp
namespace std {
    struct hash<nlohmann::basic_json>;
}
```

Return a hash value for a JSON object. The hash function tries to rely on `std::hash` where possible. Furthermore, the
type of the JSON value is taken into account, so `#!json null`, `#!cpp false`, and numbers may hash differently from
each other. Numbers that compare equal under [`operator==`](operator_eq.md) always hash equally, regardless of
whether they are stored as signed integer, unsigned integer, or floating-point number.

Numbers are hashed by their value converted to `number_float_t`. Converting an integer to `number_float_t` therefore
keeps its hash, but converting a floating-point number to an integer type is lossy and can change it: `#!cpp 0.5`
converts to `#!cpp 0`, which need not have the same hash. Unequal numbers can also share a hash value, for example two
large integers that convert to the same `number_float_t`.

## Examples

??? example

    The example shows how to calculate hash values for different JSON values.
     
    ```cpp
    --8<-- "examples/std_hash.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/std_hash.output"
    ```

    The hash values shown are examples only. They depend on the platform, the compiler, and the compiler version, and
    they can change between versions of this library. Do not persist them or rely on specific values.

## See also

- [operator==](operator_eq.md) compares two JSON values for equality, consistent with equal hash values

## Version history

- Added in version 1.0.0.
- Extended for arbitrary basic_json types in version 3.10.5.
- Numbers that compare equal hash equally since version 3.13.0; before, `#!cpp 0`, `#!cpp 0U`, and `#!cpp 0.0` had
  different hash values.
