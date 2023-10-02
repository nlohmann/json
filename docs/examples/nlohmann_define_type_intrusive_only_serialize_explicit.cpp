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
    // No default constructor
    person(std::string name_, std::string address_, int age_)
        : name(std::move(name_)), address(std::move(address_)), age(age_)
    {}

    friend void to_json(nlohmann::json& nlohmann_json_j, const person& nlohmann_json_t)
    {
        nlohmann_json_j["name"] = nlohmann_json_t.name;
        nlohmann_json_j["address"] = nlohmann_json_t.address;
        nlohmann_json_j["age"] = nlohmann_json_t.age;
    }
};
} // namespace ns

int main()
{
    ns::person p = {"Ned Flanders", "744 Evergreen Terrace", 60};

    // serialization: person -> json
    json j = p;
    std::cout << "serialization: " << j << std::endl;
}
