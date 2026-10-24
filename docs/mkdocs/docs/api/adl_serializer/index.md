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

## See also

- [Arbitrary type conversions](../../features/arbitrary_types.md) - how to make your types convertible
- [**get**](../basic_json/get.md) / [**get_to**](../basic_json/get_to.md) - convert a JSON value to a C++ type
- [**basic_json**](../basic_json/basic_json.md) - construct a JSON value from a C++ value
- [**NLOHMANN_DEFINE_TYPE_INTRUSIVE**](../macros/nlohmann_define_type_intrusive.md) - generate the conversion functions for a type
- [Specializing enum conversion](../../features/enum_conversion.md)

## Version history

- Added in version 2.1.0.
