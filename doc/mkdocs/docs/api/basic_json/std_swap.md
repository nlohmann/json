# std::swap<basic_json\>

```cpp
namespace std {
    void swap(nlohmann::basic_json& j1, nlohmann::basic_json& j2);
}
```

Exchanges the values of two JSON objects.

## Possible implementation

```cpp
void swap(nlohmann::basic_json& j1, nlohmann::basic_json& j2)
{
    j1.swap(j2);
}
```

## See also

- [swap](swap.md)

## Version history

- Added in version 1.0.0.
- Extended for arbitrary basic_json types in version 3.10.5.
