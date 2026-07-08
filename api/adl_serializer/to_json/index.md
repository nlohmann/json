# nlohmann::adl_serializer::to_json

```
template<typename BasicJsonType, typename TargetType = ValueType>
static auto to_json(BasicJsonType& j, TargetType && val) noexcept(
    noexcept(::nlohmann::to_json(j, std::forward<TargetType>(val))))
-> decltype(::nlohmann::to_json(j, std::forward<TargetType>(val)), void())
```

This function is usually called by the constructors of the [basic_json](https://json.nlohmann.me/api/basic_json/index.md) class.

## Parameters

`j` (out) : JSON value to write to

`val` (in) : value to read from

## Examples

Example

The example below shows how a `to_json` function can be implemented for a user-defined type. This function is called by the `adl_serializer` when the constructor `basic_json(ns::person)` is called.

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
void to_json(json& j, const person& p)
{
    j = json{ {"name", p.name}, {"address", p.address}, {"age", p.age} };
}
} // namespace ns

int main()
{
    ns::person p = {"Ned Flanders", "744 Evergreen Terrace", 60};

    json j = p;

    std::cout << j << std::endl;
}
```

Output:

```
{"address":"744 Evergreen Terrace","age":60,"name":"Ned Flanders"}
```

## See also

- [from_json](https://json.nlohmann.me/api/adl_serializer/from_json/index.md)

## Version history

- Added in version 2.1.0.
