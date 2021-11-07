# <small>std::</small>hash<nlohmann::basic_json\>

```cpp
namespace std {
    struct hash<nlohmann::basic_json>;
}
```

Return a hash value for a JSON object. The hash function tries to rely on `std::hash` where possible. Furthermore, the
type of the JSON value is taken into account to have different hash values for `#!json null`, `#!cpp 0`, `#!cpp 0U`, and
`#!cpp false`, etc.

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

## Version history

- Added in version 1.0.0.
- Extended for arbitrary basic_json types in version 3.10.5.
