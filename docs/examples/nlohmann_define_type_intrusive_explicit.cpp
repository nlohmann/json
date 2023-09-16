#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;
using namespace nlohmann::literals;

namespace ns
{
class person
{
  private:
    std::string name = "John Doe";
    std::string address = "123 Fake St";
    int age = -1;

  public:
    person() = default;
    person(std::string name_, std::string address_, int age_)
        : name(std::move(name_)), address(std::move(address_)), age(age_)
    {}

    friend void to_json(nlohmann::json& nlohmann_json_j, const person& nlohmann_json_t)
    {
        nlohmann_json_j["name"] = nlohmann_json_t.name;
        nlohmann_json_j["address"] = nlohmann_json_t.address;
        nlohmann_json_j["age"] = nlohmann_json_t.age;
    }

    friend void from_json(const nlohmann::json& nlohmann_json_j, person& nlohmann_json_t)
    {
        nlohmann_json_t.name = nlohmann_json_j.at("name");
        nlohmann_json_t.address = nlohmann_json_j.at("address");
        nlohmann_json_t.age = nlohmann_json_j.at("age");
    }
};
} // namespace ns

int main()
{
    ns::person p = {"Ned Flanders", "744 Evergreen Terrace", 60};

    // serialization: person -> json
    json j = p;
    std::cout << "serialization: " << j << std::endl;

    // deserialization: json -> person
    json j2 = R"({"address": "742 Evergreen Terrace", "age": 40, "name": "Homer Simpson"})"_json;
    auto p2 = j2.template get<ns::person>();

    // incomplete deserialization:
    json j3 = R"({"address": "742 Evergreen Terrace", "name": "Maggie Simpson"})"_json;
    try
    {
        auto p3 = j3.template get<ns::person>();
    }
    catch (json::exception& e)
    {
        std::cout << "deserialization failed: " << e.what() << std::endl;
    }
}
