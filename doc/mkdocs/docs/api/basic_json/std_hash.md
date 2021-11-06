# std::hash<basic_json\>

```cpp
namespace std {
    struct hash<nlohmann::basic_json>;
}
```

Return a hash value for a JSON object. The hash function tries to rely on `std::hash` where possible. Furthermore, the
type of the JSON value is taken into account to have different hash values for `#!json null`, `#!cpp 0`, `#!cpp 0U`, and
`#!cpp false`, etc.

## Version history

- Added in version 1.0.0.
- Extended for arbitrary basic_json types in version 3.10.5.
