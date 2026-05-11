# <small>nlohmann::</small>adl_serializer

```cpp
template<typename, typename>
struct adl_serializer;
```

Serializer that uses ADL ([Argument-Dependent Lookup](https://en.cppreference.com/w/cpp/language/adl)) to choose
`to_json`/`from_json` functions from the types' namespaces.

It is implemented similarly to

```cpp
template<typename ValueType>
struct adl_serializer {
    template<typename BasicJsonType>
    static void to_json(BasicJsonType& j, const T& value) {
        // calls the "to_json" method in T's namespace
    }

    template<typename BasicJsonType>
    static void from_json(const BasicJsonType& j, T& value) {
        // same thing, but with the "from_json" method
    }
};
```

## Member functions

- [**from_json**](from_json.md) - convert a JSON value to any value type
- [**to_json**](to_json.md) - convert any value type to a JSON value

## Version history

- Added in version 2.1.0.
