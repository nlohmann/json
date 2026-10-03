# Specializing enum conversion

By default, enum values are serialized to JSON as integers. In some cases, this could result in undesired behavior. If the integer values of any enum values are changed after data using those enum values has been serialized to JSON, then deserializing that JSON would result in a different enum value being restored, or the value not being found at all.

It is possible to more precisely specify how a given enum is mapped to and from JSON as shown below:

```
// example enum type declaration
enum TaskState {
    TS_STOPPED,
    TS_RUNNING,
    TS_COMPLETED,
    TS_INVALID=-1,
};

// map TaskState values to JSON as strings
NLOHMANN_JSON_SERIALIZE_ENUM( TaskState, {
    {TS_INVALID, nullptr},
    {TS_STOPPED, "stopped"},
    {TS_RUNNING, "running"},
    {TS_COMPLETED, "completed"},
})
```

The [`NLOHMANN_JSON_SERIALIZE_ENUM()` macro](https://json.nlohmann.me/api/macros/nlohmann_json_serialize_enum/index.md) declares a set of `to_json()` / `from_json()` functions for type `TaskState` while avoiding repetition and boilerplate serialization code.

## Usage

Serialization converts an enum value to its mapped string, deserialization does the reverse, and an unrecognized JSON value deserializes to the first pair in the map:

```
// enum to JSON as string
json j = TS_STOPPED;
assert(j == "stopped");

// json string to enum
json j3 = "running";
assert(j3.get<TaskState>() == TS_RUNNING);

// undefined json value to enum (where the first map entry above is the default)
json jPi = 3.14;
assert(jPi.get<TaskState>() == TS_INVALID );
```

Example: serializing/deserializing enums, including a second enum type

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

NLOHMANN_JSON_SERIALIZE_ENUM(TaskState,
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

NLOHMANN_JSON_SERIALIZE_ENUM(Color,
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

    // deserializing undefined JSON value to enum
    // (where the first map entry above is the default)
    json j_pi = 3.14;
    auto invalid = j_pi.get<ns::TaskState>();
    auto unknown = j_pi.get<ns::Color>();
    std::cout << j_pi << " -> " << invalid << ", "
              << j_pi << " -> " << static_cast<int>(unknown) << std::endl;
}
```

Output:

```
ns::TS_STOPPED -> "stopped", ns::Color::red -> "red"
"running" -> 1, "blue" -> 2
3.14 -> -1, 3.14 -> 3
```

## Notes

Just as in [Arbitrary Type Conversions](https://json.nlohmann.me/features/arbitrary_types/index.md) above,

- [`NLOHMANN_JSON_SERIALIZE_ENUM()`](https://json.nlohmann.me/api/macros/nlohmann_json_serialize_enum/index.md) MUST be declared in your enum type's namespace (which can be the global namespace), or the library will not be able to locate it, and it will default to integer serialization.
- It MUST be available (e.g., proper headers must be included) everywhere you use the conversions.

Other Important points:

- When using [`get<ENUM_TYPE>()`](https://json.nlohmann.me/api/basic_json/get/index.md), undefined JSON values will default to the first pair specified in your map. Select this default pair carefully. If you desire an exception in this circumstance use [`NLOHMANN_JSON_SERIALIZE_ENUM_STRICT()`](https://json.nlohmann.me/api/macros/nlohmann_json_serialize_enum_strict/index.md) which behaves identically except for throwing an [`out_of_range.410`](https://json.nlohmann.me/home/exceptions/#jsonexceptionout_of_range410) exception on unrecognized values, both when serializing an enum value not listed in the map and when deserializing a JSON value that matches none of the map's entries.
- If an enum or JSON value is specified more than once in your map, the first matching occurrence from the top of the map will be returned when converting to or from JSON.
- To disable the default serialization of enumerators as integers and force a compiler error instead, see [`JSON_DISABLE_ENUM_SERIALIZATION`](https://json.nlohmann.me/api/macros/json_disable_enum_serialization/index.md).

Example: `NLOHMANN_JSON_SERIALIZE_ENUM_STRICT` throwing on unrecognized values

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
