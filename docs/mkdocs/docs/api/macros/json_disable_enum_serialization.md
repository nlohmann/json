# JSON_DISABLE_ENUM_SERIALIZATION

```cpp
#define JSON_DISABLE_ENUM_SERIALIZATION /* value */
```

When defined to `1`, default serialization and deserialization functions for enums are excluded and have to be provided
by the user, for example, using [`NLOHMANN_JSON_SERIALIZE_ENUM`](nlohmann_json_serialize_enum.md) (see
[arbitrary type conversions](../../features/arbitrary_types.md) for more details).

Parsing or serializing an enum will result in a compiler error.

This works for both unscoped and scoped enums.

## Default definition

The default value is `0`.

```cpp
#define JSON_DISABLE_ENUM_SERIALIZATION 0
```

## Notes

!!! hint "CMake option"

    Enum serialization can also be controlled with the CMake option
    [`JSON_DisableEnumSerialization`](../../integration/cmake.md#json_disableenumserialization)
    (`OFF` by default) which defines `JSON_DISABLE_ENUM_SERIALIZATION` accordingly.

## Examples

??? example "Example 1: Disabled behavior"

    The code below forces the library **not** to create default serialization/deserialization functions `from_json` and `to_json`, meaning the code below
    **does not** compile.

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
        Choice ch = j.template get<Choice>();
    }
    ```

??? example "Example 2: Serialize enum macro"

    The code below forces the library **not** to create default serialization/deserialization functions `from_json` and `to_json`, but uses
    [`NLOHMANN_JSON_SERIALIZE_ENUM`](nlohmann_json_serialize_enum.md) to parse and serialize the enum.

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
        Choice ch = j.template get<Choice>();
    }
    ```

??? example "Example 3: User-defined serialization/deserialization functions"

    The code below forces the library **not** to create default serialization/deserialization functions `from_json` and `to_json`, but uses user-defined
    functions to parse and serialize the enum.

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
        auto value = j.template get<std::string>();
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
        auto value = j.template get<std::string>();
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
        Choice ch = j.template get<Choice>();
    }
    ```

## See also

- [:simple-cmake: JSON_DisableEnumSerialization](../../integration/cmake.md#json_disableenumserialization) - CMake option to control
  the macro
- [`NLOHMANN_JSON_SERIALIZE_ENUM`](nlohmann_json_serialize_enum.md) - serialize/deserialize an enum

## Version history

- Added in version 3.11.0.
