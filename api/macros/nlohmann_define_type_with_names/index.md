# NLOHMANN_DEFINE_TYPE_INTRUSIVE_WITH_NAMES, NLOHMANN_DEFINE_TYPE_INTRUSIVE_WITH_DEFAULT_WITH_NAMES, NLOHMANN_DEFINE_TYPE_INTRUSIVE_ONLY_SERIALIZE_WITH_NAMES, NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_WITH_NAMES, NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_WITH_DEFAULT_WITH_NAMES, NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_ONLY_SERIALIZE_WITH_NAMES, NLOHMANN_DEFINE_DERIVED_TYPE_INTRUSIVE_WITH_NAMES, NLOHMANN_DEFINE_DERIVED_TYPE_INTRUSIVE_WITH_DEFAULT_WITH_NAMES, NLOHMANN_DEFINE_DERIVED_TYPE_INTRUSIVE_ONLY_SERIALIZE_WITH_NAMES, NLOHMANN_DEFINE_DERIVED_TYPE_NON_INTRUSIVE_WITH_NAMES, NLOHMANN_DEFINE_DERIVED_TYPE_NON_INTRUSIVE_WITH_DEFAULT_WITH_NAMES, NLOHMANN_DEFINE_DERIVED_TYPE_NON_INTRUSIVE_ONLY_SERIALIZE_WITH_NAMES

```
#define NLOHMANN_DEFINE_TYPE_INTRUSIVE_WITH_NAMES(type, "json_member_name", member...)
#define NLOHMANN_DEFINE_TYPE_INTRUSIVE_WITH_DEFAULT_WITH_NAMES(type, "json_member_name", member...)
#define NLOHMANN_DEFINE_TYPE_INTRUSIVE_ONLY_SERIALIZE_WITH_NAMES(type, "json_member_name", member...)
#define NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_WITH_NAMES(type, "json_member_name", member...)
#define NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_WITH_DEFAULT_WITH_NAMES(type, "json_member_name", member...)
#define NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_ONLY_SERIALIZE_WITH_NAMES(type, "json_member_name", member...)
#define NLOHMANN_DEFINE_DERIVED_TYPE_INTRUSIVE_WITH_NAMES(type, base_type, "json_member_name", member...)
#define NLOHMANN_DEFINE_DERIVED_TYPE_INTRUSIVE_WITH_DEFAULT_WITH_NAMES(type, base_type, "json_member_name", member...)
#define NLOHMANN_DEFINE_DERIVED_TYPE_INTRUSIVE_ONLY_SERIALIZE_WITH_NAMES(type, base_type, "json_member_name", member...)
#define NLOHMANN_DEFINE_DERIVED_TYPE_NON_INTRUSIVE_WITH_NAMES(type, base_type, "json_member_name", member...)
#define NLOHMANN_DEFINE_DERIVED_TYPE_NON_INTRUSIVE_WITH_DEFAULT_WITH_NAMES(type, base_type, "json_member_name", member...)
#define NLOHMANN_DEFINE_DERIVED_TYPE_NON_INTRUSIVE_ONLY_SERIALIZE_WITH_NAMES(type, base_type, "json_member_name", member...)
```

These macros can be used in case you want to use the custom names for the member variables in the resulting JSON. They behave exactly as their non-`WITH_NAMES` counterparts, but require an additional parameter for each member variable which will be used in JSON. Both serialization and deserialization will only use the custom names for JSON, the names of the member variables themselves will be ignored.

Using the named conversion macros will halve the maximum number of member variables from 63 to 31.

For further information please refer to the corresponding macros without `WITH_NAMES`.

## Parameters

`type` (in) : name of the type (class, struct) to serialize/deserialize

`base_type` (in) : name of the base type (class, struct) `type` is derived from (used only in `DEFINE_DERIVED_TYPE` macros)

`json_member_name` (in) : the string that will be used as the name for the next value

`member` (in) : name of the member variable to serialize/deserialize

## Examples

Example (1): NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_WITH_NAMES

Consider the following complete example:

```
#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;
using namespace nlohmann::literals;

namespace ns
{
struct person
{
    std::string name;
    std::string address;
    int age;
};

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_WITH_NAMES(person, "json_name", name, "json_address", address, "json_age", age)
} // namespace ns

int main()
{
    ns::person p = {"Ned Flanders", "744 Evergreen Terrace", 60};

    // serialization: person -> json
    json j = p;
    std::cout << "serialization: " << j << std::endl;

    // deserialization: json -> person
    json j2 = R"({"json_address": "742 Evergreen Terrace", "json_age": 40, "json_name": "Homer Simpson"})"_json;
    auto p2 = j2.template get<ns::person>();

    // incomplete deserialization:
    json j3 = R"({"json_address": "742 Evergreen Terrace", "json_name": "Maggie Simpson"})"_json;
    try
    {
        auto p3 = j3.template get<ns::person>();
    }
    catch (const json::exception& e)
    {
        std::cout << "deserialization failed: " << e.what() << std::endl;
    }
}
```

Output:

```
serialization: {"json_address":"744 Evergreen Terrace","json_age":60,"json_name":"Ned Flanders"}
deserialization failed: [json.exception.out_of_range.403] key 'json_age' not found
```

Notes:

- `ns::person` is default-constructible. This is a requirement for using the macro.
- `ns::person` has only public member variables. This makes `NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_WITH_NAMES` applicable.
- The macro `NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_WITH_NAMES` is used *outside* the class, but *inside* its namespace `ns`.
- A missing key "age" in the deserialization yields an exception. To fall back to the default value, `NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_WITH_DEFAULT_WITH_NAMES` can be used.

The macro is equivalent to:

```
#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;
using namespace nlohmann::literals;

namespace ns
{
struct person
{
    std::string name;
    std::string address;
    int age;
};

template <typename BasicJsonType, nlohmann::detail::enable_if_t<nlohmann::detail::is_basic_json<BasicJsonType>::value, int> = 0>
void to_json(BasicJsonType& nlohmann_json_j, const person& nlohmann_json_t)
{
    nlohmann_json_j["json_name"] = nlohmann_json_t.name;
    nlohmann_json_j["json_address"] = nlohmann_json_t.address;
    nlohmann_json_j["json_age"] = nlohmann_json_t.age;
}

template <typename BasicJsonType, nlohmann::detail::enable_if_t<nlohmann::detail::is_basic_json<BasicJsonType>::value, int> = 0>
void from_json(const BasicJsonType& nlohmann_json_j, person& nlohmann_json_t)
{
    nlohmann_json_j.at("json_name").get_to(nlohmann_json_t.name);
    nlohmann_json_j.at("json_address").get_to(nlohmann_json_t.address);
    nlohmann_json_j.at("json_age").get_to(nlohmann_json_t.age);
}
} // namespace ns

int main()
{
    ns::person p = {"Ned Flanders", "744 Evergreen Terrace", 60};

    // serialization: person -> json
    json j = p;
    std::cout << "serialization: " << j << std::endl;

    // deserialization: json -> person
    json j2 = R"({"json_address": "742 Evergreen Terrace", "json_age": 40, "json_name": "Homer Simpson"})"_json;
    auto p2 = j2.template get<ns::person>();

    // incomplete deserialization:
    json j3 = R"({"json_address": "742 Evergreen Terrace", "json_name": "Maggie Simpson"})"_json;
    try
    {
        auto p3 = j3.template get<ns::person>();
    }
    catch (const json::exception& e)
    {
        std::cout << "deserialization failed: " << e.what() << std::endl;
    }
}
```

## Version history

1. Added in version 3.12.x.
