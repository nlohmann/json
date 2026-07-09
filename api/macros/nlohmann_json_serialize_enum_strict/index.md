# NLOHMANN_JSON_SERIALIZE_ENUM_STRICT

```
#define NLOHMANN_JSON_SERIALIZE_ENUM_STRICT(type, conversion...)
```

By default, enum values are serialized to JSON as integers. In some cases, this could result in undesired behavior. If an enum is modified or re-ordered after data has been serialized to JSON, the later deserialized JSON data may be undefined or a different enum value than was originally intended.

`NLOHMANN_JSON_SERIALIZE_ENUM_STRICT` allows to define a user-defined serialization for every enumerator that throws an exception on undefined input.

## Parameters

`type` (in) : name of the enum to serialize/deserialize

`conversion` (in) : a pair of an enumerator and a JSON serialization; arbitrary pairs can be given as a comma-separated list

## Default definition

The macro adds two functions to the namespace which take care of the serialization and deserialization:

```
template<typename BasicJsonType>
inline void to_json(BasicJsonType& j, const type& e);
template<typename BasicJsonType>
inline void from_json(const BasicJsonType& j, type& e);
```

## Notes

Prerequisites

The macro must be used inside the namespace of the enum.

Important notes

- Undefined input throws [`out_of_range.410`](https://json.nlohmann.me/home/exceptions/#jsonexceptionout_of_range410) in both directions: when serializing an enum value not listed in the conversions, and when deserializing (e.g., via [`get<ENUM_TYPE>()`](https://json.nlohmann.me/api/basic_json/get/index.md)) a JSON value that matches no conversion; example: `"enum value out of range for <type>"`.
- If an enum or JSON value is specified in multiple conversions, the first matching conversion from the top of the list will be returned when converting to or from JSON. See example 2 below.

## Examples

Example 1: Basic usage

The example shows how `NLOHMANN_JSON_SERIALIZE_ENUM_STRICT` can be used to serialize/deserialize both classical enums and C++11 enum classes:

```
#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

namespace ns
{
enum TaskState
{
    TS_STOPPED,
    TS_RUNNING,
    TS_COMPLETED,
    TS_INVALID = -1
};

NLOHMANN_JSON_SERIALIZE_ENUM_STRICT(TaskState,
{
    { TS_INVALID, nullptr },
    { TS_STOPPED, "stopped" },
    { TS_RUNNING, "running" },
    { TS_COMPLETED, "completed" }
})

enum class Color
{
    red, green, blue, unknown
};

NLOHMANN_JSON_SERIALIZE_ENUM_STRICT(Color,
{
    { Color::unknown, "unknown" }, { Color::red, "red" },
    { Color::green, "green" }, { Color::blue, "blue" }
})
} // namespace ns

int main()
{
    // serialization
    json j_stopped = ns::TS_STOPPED;
    json j_red = ns::Color::red;
    std::cout << "ns::TS_STOPPED -> " << j_stopped
              << ", ns::Color::red -> " << j_red << std::endl;

    // deserialization
    json j_running = "running";
    json j_blue = "blue";
    auto running = j_running.get<ns::TaskState>();
    auto blue = j_blue.get<ns::Color>();
    std::cout << j_running << " -> " << running
              << ", " << j_blue << " -> " << static_cast<int>(blue) << std::endl;

}
```

Output:

```
ns::TS_STOPPED -> "stopped", ns::Color::red -> "red"
"running" -> 1, "blue" -> 2
```

Example 2: Multiple conversions for one enumerator

The example shows how to use multiple conversions for a single enumerator. In the example, `Color::red` will always be *serialized* to `"red"`, because the first occurring conversion. The second conversion, however, offers an alternative *deserialization* from `"rot"` to `Color::red`.

```
#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

namespace ns
{
enum class Color
{
    red, green, blue, unknown
};

NLOHMANN_JSON_SERIALIZE_ENUM_STRICT(Color,
{
    { Color::unknown, "unknown" }, { Color::red, "red" },
    { Color::green, "green" }, { Color::blue, "blue" },
    { Color::red, "rot" } // a second conversion for Color::red
})
}

int main()
{
    // serialization
    json j_red = ns::Color::red;
    std::cout << static_cast<int>(ns::Color::red) << " -> " << j_red << std::endl;

    // deserialization
    json j_rot = "rot";
    auto rot = j_rot.get<ns::Color>();
    auto red = j_red.get<ns::Color>();
    std::cout << j_rot << " -> " << static_cast<int>(rot) << std::endl;
    std::cout << j_red << " -> " << static_cast<int>(red) << std::endl;
}
```

Output:

```
0 -> "red"
"rot" -> 0
"red" -> 0
```

Example 3: exceptions on invalid serialization

The example shows how an invalid serialization causes an exception to be thrown. In the example, Color::unknown is not defined in the mapping used to call `NLOHMANN_JSON_SERIALIZE_ENUM_STRICT` so causes an exception when used to serialize. Similarly, "what" does not refer to an enum value so also causes an exception when deserialization is attempted.

```
#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

namespace ns
{

enum class Color
{
    red,
    green,
    blue,
    unknown // not mapped in JSON_SERIALIZE_ENUM_STRICT
};

NLOHMANN_JSON_SERIALIZE_ENUM_STRICT(Color,
{
    {Color::red, "red"},
    {Color::green, "green"},
    {Color::blue, "blue"}
})

} // namespace ns


int main()
{
    // invalid serialization
    try
    {
        // ns::color::unknown was not mapped in macro
        json invalid_serialization = ns::Color::unknown;
    }
    catch (const json::exception e)
    {
        std::cout << "deserialization failed: " << e.what() << std::endl;
    }

    // invalid deserialization
    try
    {
        // what does not map to an enum
        json invalid_deserialization("what");
        ns::Color color = invalid_deserialization.get<ns::Color>();
    }
    catch (const json::exception e)
    {
        std::cout << "deserialization failed: " << e.what() << std::endl;
    }

    return 0;
}
```

Output:

```
deserialization failed: [json.exception.out_of_range.410] enum value out of range for Color
deserialization failed: [json.exception.out_of_range.410] enum value out of range for Color: "what"
```

## See also

- [Specializing enum conversion](https://json.nlohmann.me/features/enum_conversion/index.md)
- [`NLOHMANN_JSON_SERIALIZE_ENUM`](https://json.nlohmann.me/api/macros/nlohmann_json_serialize_enum/index.md)
- [`JSON_DISABLE_ENUM_SERIALIZATION`](https://json.nlohmann.me/api/macros/json_disable_enum_serialization/index.md)

## Version history

Added in version 3.13.0.
