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
