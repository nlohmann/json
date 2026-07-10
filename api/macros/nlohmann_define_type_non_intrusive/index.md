# NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE, NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_WITH_DEFAULT, NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_ONLY_SERIALIZE

```
#define NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(type, member...)              // (1)
#define NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_WITH_DEFAULT(type, member...) // (2)
#define NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_ONLY_SERIALIZE(type, member...) // (3)
```

These macros can be used to simplify the serialization/deserialization of types if you want to use a JSON object as serialization and want to use the member variable names as object keys in that object. The macro is to be defined **outside** the class/struct to create code for, but **inside** its namespace. Unlike [`NLOHMANN_DEFINE_TYPE_INTRUSIVE`](https://json.nlohmann.me/api/macros/nlohmann_define_type_intrusive/index.md), it **cannot** access private members. The first parameter is the name of the class/struct, and all remaining parameters name the members.

1. Will use [`at`](https://json.nlohmann.me/api/basic_json/at/index.md) during deserialization and will throw [`out_of_range.403`](https://json.nlohmann.me/home/exceptions/#jsonexceptionout_of_range403) if a key is missing in the JSON object.
1. Will use [`value`](https://json.nlohmann.me/api/basic_json/value/index.md) during deserialization and fall back to the default value for the respective type of the member variable if a key in the JSON object is missing. The generated `from_json()` function default constructs an object and uses its values as the defaults when calling the `value` function.
1. Only defines the serialization. Useful in cases when the type does not have a default constructor and only serialization is required.

Summary:

| Need access to private members | Need only serialization | Allow missing values when de-serializing | macro                                                 |
| ------------------------------ | ----------------------- | ---------------------------------------- | ----------------------------------------------------- |
|                                |                         |                                          | **NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE**                |
|                                |                         |                                          | **NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_WITH_DEFAULT**   |
|                                |                         |                                          | **NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_ONLY_SERIALIZE** |

## Parameters

`type` (in) : name of the type (class, struct) to serialize/deserialize

`member` (in) : name of the (public) member variable to serialize/deserialize; up to 63 members can be given as a comma-separated list

## Default definition

The macros add two functions to the namespace which take care of the serialization and deserialization:

```
template<typename BasicJsonType>
void to_json(BasicJsonType&, const type&);
template<typename BasicJsonType>
void from_json(const BasicJsonType&, type&); // except (3)
```

See the examples below for the concrete generated code.

## Notes

Prerequisites

1. The type `type` must be default constructible (except (3). See [How can I use `get()` for non-default constructible/non-copyable types?](https://json.nlohmann.me/features/arbitrary_types/#how-can-i-use-get-for-non-default-constructiblenon-copyable-types) for how to overcome this limitation.
1. The macro must be used outside the type (class/struct).
1. The passed members must be public.

Implementation limits

- The current implementation is limited to at most 63 member variables. If you want to serialize/deserialize types with more than 63 member variables, you need to define the `to_json`/`from_json` functions manually.
- These macros always produce object-style (named-key) JSON, one key per member. There is no macro variant that serializes a struct's members positionally into a JSON array; for that, write `to_json`/`from_json` by hand, building/reading a `json::array()` of the members in order.

## Examples

Example (1): NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE

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

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(person, name, address, age)
} // namespace ns

int main()
{
    ns::person p = {"Ned Flanders", "744 Evergreen Terrace", 60};

    // serialization: person -> json
    json j = p;
    std::cout << "serialization: " << j << std::endl;

    // deserialization: json -> person
    json j2 = R"({"address": "742 Evergreen Terrace", "age": 40, "name": "Homer Simpson"})"_json;
    auto p2 = j2.get<ns::person>();

    // incomplete deserialization:
    json j3 = R"({"address": "742 Evergreen Terrace", "name": "Maggie Simpson"})"_json;
    try
    {
        auto p3 = j3.get<ns::person>();
    }
    catch (const json::exception& e)
    {
        std::cout << "deserialization failed: " << e.what() << std::endl;
    }
}
```

Output:

```
serialization: {"address":"744 Evergreen Terrace","age":60,"name":"Ned Flanders"}
deserialization failed: [json.exception.out_of_range.403] key 'age' not found
```

Notes:

- `ns::person` is default-constructible. This is a requirement for using the macro.
- `ns::person` has only public member variables. This makes `NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE` applicable.
- The macro `NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE` is used *outside* the class, but *inside* its namespace `ns`.
- A missing key "age" in the deserialization yields an exception. To fall back to the default value, `NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_WITH_DEFAULT` can be used.

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

template<typename BasicJsonType>
void to_json(BasicJsonType& nlohmann_json_j, const person& nlohmann_json_t)
{
    nlohmann_json_j["name"] = nlohmann_json_t.name;
    nlohmann_json_j["address"] = nlohmann_json_t.address;
    nlohmann_json_j["age"] = nlohmann_json_t.age;
}

template<typename BasicJsonType>
void from_json(const BasicJsonType& nlohmann_json_j, person& nlohmann_json_t)
{
    nlohmann_json_t.name = nlohmann_json_j.at("name");
    nlohmann_json_t.address = nlohmann_json_j.at("address");
    nlohmann_json_t.age = nlohmann_json_j.at("age");
}
} // namespace ns

int main()
{
    ns::person p = {"Ned Flanders", "744 Evergreen Terrace", 60};

    // serialization: person -> json
    json j = p;
    std::cout << "serialization: " << j << std::endl;

    // deserialization: json -> person
    json j2 = R"({"address": "742 Evergreen Terrace", "age": 40, "name": "Homer Simpson"})"_json;
    auto p2 = j2.get<ns::person>();

    // incomplete deserialization:
    json j3 = R"({"address": "742 Evergreen Terrace", "name": "Maggie Simpson"})"_json;
    try
    {
        auto p3 = j3.get<ns::person>();
    }
    catch (const json::exception& e)
    {
        std::cout << "deserialization failed: " << e.what() << std::endl;
    }
}
```

Example (2): NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_WITH_DEFAULT

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
    std::string name = "John Doe";
    std::string address = "123 Fake St";
    int age = -1;

    person() = default;
    person(std::string name_, std::string address_, int age_)
        : name(std::move(name_)), address(std::move(address_)), age(age_)
    {}
};

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_WITH_DEFAULT(person, name, address, age)
} // namespace ns

int main()
{
    ns::person p = {"Ned Flanders", "744 Evergreen Terrace", 60};

    // serialization: person -> json
    json j = p;
    std::cout << "serialization: " << j << std::endl;

    // deserialization: json -> person
    json j2 = R"({"address": "742 Evergreen Terrace", "age": 40, "name": "Homer Simpson"})"_json;
    auto p2 = j2.get<ns::person>();

    // incomplete deserialization:
    json j3 = R"({"address": "742 Evergreen Terrace", "name": "Maggie Simpson"})"_json;
    auto p3 = j3.get<ns::person>();
    std::cout << "roundtrip: " << json(p3) << std::endl;
}
```

Output:

```
serialization: {"address":"744 Evergreen Terrace","age":60,"name":"Ned Flanders"}
roundtrip: {"address":"742 Evergreen Terrace","age":-1,"name":"Maggie Simpson"}
```

Notes:

- `ns::person` is default-constructible. This is a requirement for using the macro.
- `ns::person` has only public member variables. This makes `NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_WITH_DEFAULT` applicable.
- The macro `NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_WITH_DEFAULT` is used *outside* the class, but *inside* its namespace `ns`.
- A missing key "age" in the deserialization does not yield an exception. Instead, the default value `-1` is used.

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
    std::string name = "John Doe";
    std::string address = "123 Fake St";
    int age = -1;

    person() = default;
    person(std::string name_, std::string address_, int age_)
        : name(std::move(name_)), address(std::move(address_)), age(age_)
    {}
};

template<typename BasicJsonType>
void to_json(BasicJsonType& nlohmann_json_j, const person& nlohmann_json_t)
{
    nlohmann_json_j["name"] = nlohmann_json_t.name;
    nlohmann_json_j["address"] = nlohmann_json_t.address;
    nlohmann_json_j["age"] = nlohmann_json_t.age;
}

template<typename BasicJsonType>
void from_json(const BasicJsonType& nlohmann_json_j, person& nlohmann_json_t)
{
    person nlohmann_json_default_obj;
    nlohmann_json_t.name = nlohmann_json_j.value("name", nlohmann_json_default_obj.name);
    nlohmann_json_t.address = nlohmann_json_j.value("address", nlohmann_json_default_obj.address);
    nlohmann_json_t.age = nlohmann_json_j.value("age", nlohmann_json_default_obj.age);
}
} // namespace ns

int main()
{
    ns::person p = {"Ned Flanders", "744 Evergreen Terrace", 60};

    // serialization: person -> json
    json j = p;
    std::cout << "serialization: " << j << std::endl;

    // deserialization: json -> person
    json j2 = R"({"address": "742 Evergreen Terrace", "age": 40, "name": "Homer Simpson"})"_json;
    auto p2 = j2.get<ns::person>();

    // incomplete deserialization:
    json j3 = R"({"address": "742 Evergreen Terrace", "name": "Maggie Simpson"})"_json;
    auto p3 = j3.get<ns::person>();
    std::cout << "roundtrip: " << json(p3) << std::endl;
}
```

Note how a default-initialized `person` object is used in the `from_json` to fill missing values.

Example (3): NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_ONLY_SERIALIZE

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

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_ONLY_SERIALIZE(person, name, address, age)
} // namespace ns

int main()
{
    ns::person p = {"Ned Flanders", "744 Evergreen Terrace", 60};

    // serialization: person -> json
    json j = p;
    std::cout << "serialization: " << j << std::endl;
}
```

Output:

```
serialization: {"address":"744 Evergreen Terrace","age":60,"name":"Ned Flanders"}
```

Notes:

- `ns::person` is non-default-constructible. This allows this macro to be used instead of `NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE` and `NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_WITH_DEFAULT`.
- `ns::person` has only public member variables. This makes `NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_ONLY_SERIALIZE` applicable.
- The macro `NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_ONLY_SERIALIZE` is used *outside* the class, but *inside* its namespace `ns`.

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

template<typename BasicJsonType>
void to_json(BasicJsonType& nlohmann_json_j, const person& nlohmann_json_t)
{
    nlohmann_json_j["name"] = nlohmann_json_t.name;
    nlohmann_json_j["address"] = nlohmann_json_t.address;
    nlohmann_json_j["age"] = nlohmann_json_t.age;
}
} // namespace ns

int main()
{
    ns::person p = {"Ned Flanders", "744 Evergreen Terrace", 60};

    // serialization: person -> json
    json j = p;
    std::cout << "serialization: " << j << std::endl;
}
```

## See also

- [NLOHMANN_DEFINE_TYPE_INTRUSIVE, NLOHMANN_DEFINE_TYPE_INTRUSIVE_WITH_DEFAULT, NLOHMANN_DEFINE_TYPE_INTRUSIVE_ONLY_SERIALIZE](https://json.nlohmann.me/api/macros/nlohmann_define_type_intrusive/index.md) for a similar macro that can be defined *inside* the type.
- [NLOHMANN_DEFINE_DERIVED_TYPE_INTRUSIVE, NLOHMANN_DEFINE_DERIVED_TYPE_INTRUSIVE_WITH_DEFAULT, NLOHMANN_DEFINE_DERIVED_TYPE_INTRUSIVE_ONLY_SERIALIZE, NLOHMANN_DEFINE_DERIVED_TYPE_NON_INTRUSIVE, NLOHMANN_DEFINE_DERIVED_TYPE_NON_INTRUSIVE_WITH_DEFAULT, NLOHMANN_DEFINE_DERIVED_TYPE_NON_INTRUSIVE_ONLY_SERIALIZE](https://json.nlohmann.me/api/macros/nlohmann_define_derived_type/index.md) for similar macros for derived types
- [Arbitrary Type Conversions](https://json.nlohmann.me/features/arbitrary_types/index.md) for an overview.

## Version history

1. Added in version 3.9.0.
1. Added in version 3.11.0.
1. Added in version 3.11.3.
