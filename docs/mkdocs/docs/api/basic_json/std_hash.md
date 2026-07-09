# <small>std::</small>hash<nlohmann::basic_json\>

```cpp
namespace std {
    struct hash<nlohmann::basic_json>;
}
```

Return a hash value for a JSON object. The hash function tries to rely on `std::hash` where possible. To satisfy the
`std::hash` contract, numeric JSON values that compare equal must hash to the same value. This means:

- `json(42)`, `json(42u)`, and `json(42.0)` all hash to the same value
- `json(0)`, `json(0u)`, and `json(0.0)` all hash to the same value

Different types hash differently for non-numeric types (e.g., `#!json null`, `#!cpp false`, and strings all have distinct hashes).

**Edge case:** For very large integers outside the exact representable range of the floating-point type (beyond ~2^53 for
typical `double`), the hash values for integer and floating-point values may differ, even if the floating-point value
was obtained by casting the integer (due to precision loss). This is a documented limitation arising from how the
comparison operator normalizes numeric types.

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

    Note the output is platform-dependent.

## Version history

- Added in version 1.0.0.
- Extended for arbitrary basic_json types in version 3.10.5.
