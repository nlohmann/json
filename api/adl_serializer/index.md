# nlohmann::adl_serializer

```
template<typename, typename>
struct adl_serializer;
```

Serializer that uses ADL ([Argument-Dependent Lookup](https://en.cppreference.com/w/cpp/language/adl)) to choose `to_json`/`from_json` functions from the types' namespaces.

It is implemented similarly to

```
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

- [**from_json**](https://json.nlohmann.me/api/adl_serializer/from_json/index.md) - convert a JSON value to any value type
- [**to_json**](https://json.nlohmann.me/api/adl_serializer/to_json/index.md) - convert any value type to a JSON value

## See also

- [Arbitrary type conversions](https://json.nlohmann.me/features/arbitrary_types/index.md) - how to make your types convertible
- [`get`](https://json.nlohmann.me/api/basic_json/get/index.md) - / [`get_to`](https://json.nlohmann.me/api/basic_json/get_to/index.md) - convert a JSON value to a C++ type
- [`basic_json`](https://json.nlohmann.me/api/basic_json/basic_json/index.md) - construct a JSON value from a C++ value
- [`NLOHMANN_DEFINE_TYPE_INTRUSIVE`](https://json.nlohmann.me/api/macros/nlohmann_define_type_intrusive/index.md) - generate the conversion functions for a type
- [Specializing enum conversion](https://json.nlohmann.me/features/enum_conversion/index.md) - serializing enums as JSON strings

## Version history

- Added in version 2.1.0.
