# nlohmann::adl_serializer::from_json

```
// (1)
template<typename BasicJsonType, typename TargetType = ValueType>
static auto from_json(BasicJsonType && j, TargetType& val) noexcept(
    noexcept(::nlohmann::from_json(std::forward<BasicJsonType>(j), val)))
-> decltype(::nlohmann::from_json(std::forward<BasicJsonType>(j), val), void())

// (2)
template<typename BasicJsonType, typename TargetType = ValueType>
static auto from_json(BasicJsonType && j) noexcept(
noexcept(::nlohmann::from_json(std::forward<BasicJsonType>(j), detail::identity_tag<TargetType> {})))
-> decltype(::nlohmann::from_json(std::forward<BasicJsonType>(j), detail::identity_tag<TargetType> {}))
```

This function is usually called by the [`get()`](https://json.nlohmann.me/api/basic_json/get/index.md) function of the [basic_json](https://json.nlohmann.me/api/basic_json/index.md) class (either explicitly or via the conversion operators).

1. This function is chosen for default-constructible value types.
1. This function is chosen for value types which are not default-constructible.

## Parameters

`j` (in) : JSON value to read from

`val` (out) : value to write to

## Return value

1. (none) -- the converted value is written to the output parameter `val`.
1. the JSON value `j` converted to `TargetType`

## Examples

Example: (1) Default-constructible type

The example below shows how a `from_json` function can be implemented for a user-defined type. This function is called by the `adl_serializer` when `get<ns::person>()` is called.

```
#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

namespace ns
{
// a simple struct to model a person
struct person
{
    std::string name;
    std::string address;
    int age;
};
} // namespace ns

namespace ns
{
void from_json(const json& j, person& p)
{
    j.at("name").get_to(p.name);
    j.at("address").get_to(p.address);
    j.at("age").get_to(p.age);
}
} // namespace ns

int main()
{
    json j;
    j["name"] = "Ned Flanders";
    j["address"] = "744 Evergreen Terrace";
    j["age"] = 60;

    auto p = j.get<ns::person>();

    std::cout << p.name << " (" << p.age << ") lives in " << p.address << std::endl;
}
```

Output:

```
Ned Flanders (60) lives in 744 Evergreen Terrace
```

Example: (2) Non-default-constructible type

The example below shows how a `from_json` is implemented as part of a specialization of the `adl_serializer` to realize the conversion of a non-default-constructible type.

```
#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

namespace ns
{
// a simple struct to model a person (not default constructible)
struct person
{
    person(std::string n, std::string a, int aa)
        : name(std::move(n)), address(std::move(a)), age(aa)
    {}

    std::string name;
    std::string address;
    int age;
};
} // namespace ns

namespace nlohmann
{
template <>
struct adl_serializer<ns::person>
{
    static ns::person from_json(const json& j)
    {
        return {j.at("name"), j.at("address"), j.at("age")};
    }

    // Here's the catch! You must provide a to_json method! Otherwise, you
    // will not be able to convert person to json, since you fully
    // specialized adl_serializer on that type
    static void to_json(json& j, ns::person p)
    {
        j["name"] = p.name;
        j["address"] = p.address;
        j["age"] = p.age;
    }
};
} // namespace nlohmann

int main()
{
    json j;
    j["name"] = "Ned Flanders";
    j["address"] = "744 Evergreen Terrace";
    j["age"] = 60;

    auto p = j.get<ns::person>();

    std::cout << p.name << " (" << p.age << ") lives in " << p.address << std::endl;
}
```

Output:

```
Ned Flanders (60) lives in 744 Evergreen Terrace
```

## See also

- [to_json](https://json.nlohmann.me/api/adl_serializer/to_json/index.md)

## Version history

- Added in version 2.1.0.
