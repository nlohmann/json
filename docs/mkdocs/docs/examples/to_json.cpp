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
