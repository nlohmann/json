# JSON_DISABLE_ENUM_SERIALIZATION

```cpp
#define JSON_DISABLE_ENUM_SERIALIZATION
```

When defined, default serialization and deserialization functions for enums are excluded and have to be provided by the user, for example, using [`NLOHMANN_JSON_SERIALIZE_ENUM`](nlohmann_json_serialize_enum.md) (see [arbitrary type conversions](../../features/arbitrary_types.md) for more details).

Parsing or serializing an enum will result in a compiler error.

This works for both unscoped and scoped enums.

## Default definition

By default, `#!cpp JSON_DISABLE_ENUM_SERIALIZATION` is not defined.

```cpp
#undef JSON_DISABLE_ENUM_SERIALIZATION
```

## Examples

??? example "Example 1: Disabled behavior"

    The code below forces the library **not** to create default serialization/deserialization functions `from_json` and `to_json`, meaning the code below **does not** compile.

    ```cpp
    #define JSON_DISABLE_ENUM_SERIALIZATION 1
    #include <nlohmann/json.hpp>

    using json = nlohmann::json;

    enum class Choice
    {
        first,
        second,
    };
    
    int main()
    {
        // normally invokes to_json serialization function but with JSON_DISABLE_ENUM_SERIALIZATION defined, it does not
        const json j = Choice::first; 

        // normally invokes from_json parse function but with JSON_DISABLE_ENUM_SERIALIZATION defined, it does not
        Choice ch = j.get<Choice>();
    }
    ```

??? example "Example 2: Serialize enum macro"

    The code below forces the library **not** to create default serialization/deserialization functions `from_json` and `to_json`, but uses [`NLOHMANN_JSON_SERIALIZE_ENUM`](nlohmann_json_serialize_enum.md) to parse and serialize the enum.

    ```cpp
    #define JSON_DISABLE_ENUM_SERIALIZATION 1
    #include <nlohmann/json.hpp>

    using json = nlohmann::json;

    enum class Choice
    {
        first,
        second,
    };

    NLOHMANN_JSON_SERIALIZE_ENUM(Choice,
    {
        { Choice::first, "first" },
        { Choice::second, "second" },
    })
    
    int main()
    {
        // uses user-defined to_json function defined by macro
        const json j = Choice::first; 

        // uses user-defined from_json function defined by macro
        Choice ch = j.get<Choice>();
    }
    ```

??? example "Example 3: User-defined serialization/deserialization functions"

    The code below forces the library **not** to create default serialization/deserialization functions `from_json` and `to_json`, but uses user-defined functions to parse and serialize the enum.

    ```cpp
    #define JSON_DISABLE_ENUM_SERIALIZATION 1
    #include <nlohmann/json.hpp>

    using json = nlohmann::json;

    enum class Choice
    {
        first,
        second,
    };

    void from_json(const json& j, Choice& ch)
    {
        auto value = j.get<std::string>();
        if (value == "first")
        {
            ch = Choice::first;
        }
        else if (value == "second")
        {
            ch = Choice::second;
        }
    }

    void to_json(json& j, const Choice& ch)
    {
        auto value = j.get<std::string>();
        if (value == "first")
        {
            ch = Choice::first;
        }
        else if (value == "second")
        {
            ch = Choice::second;
        }
    }
    
    int main()
    {
        // uses user-defined to_json function
        const json j = Choice::first; 

        // uses user-defined from_json function
        Choice ch = j.get<Choice>();
    }
    ```

## See also

- [`NLOHMANN_JSON_SERIALIZE_ENUM`](nlohmann_json_serialize_enum.md)