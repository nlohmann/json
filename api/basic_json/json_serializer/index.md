# nlohmann::basic_json::json_serializer

```
template<typename T, typename SFINAE>
using json_serializer = JSONSerializer<T, SFINAE>;
```

## Template parameters

`T` : type to convert; will be used in the `to_json`/`from_json` functions

`SFINAE` : type to add compile type checks via SFINAE; usually `void`

## Notes

#### Default type

The default values for `json_serializer` is [`adl_serializer`](https://json.nlohmann.me/api/adl_serializer/index.md).

## Examples

Example

The example below shows how a conversion of a non-default-constructible type is implemented via a specialization of the `adl_serializer`.

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

## Version history

- Since version 2.0.0.
