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
