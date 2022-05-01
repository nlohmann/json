#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

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

    NLOHMANN_DEFINE_TYPE_INTRUSIVE_WITH_DEFAULT(person, name, address, age)
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
    auto p2 = j2.get<ns::person>();

    // incomplete deserialization:
    json j3 = R"({"address": "742 Evergreen Terrace", "name": "Maggie Simpson"})"_json;
    auto p3 = j3.get<ns::person>();
    std::cout << "roundtrip: " << json(p3) << std::endl;
}
