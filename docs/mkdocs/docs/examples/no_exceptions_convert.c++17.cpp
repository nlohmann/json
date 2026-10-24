#include <iostream>
#include <optional>
#include <string>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

struct person
{
    std::string name;
    int age;
};

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(person, name, age)

// Compile this function with exceptions enabled and call it from code that does not use them.
std::optional<person> to_person(const json& j)
{
    try
    {
        return j.get<person>();
    }
    catch (const json::exception&)
    {
        return std::nullopt;
    }
}

int main()
{
    const json good = {{"name", "Mary"}, {"age", 42}};
    const json bad = {{"name", "Mary"}, {"age", "forty-two"}};
    const json incomplete = {{"name", "Mary"}};

    for (const json& j : {good, bad, incomplete})
    {
        if (const auto p = to_person(j))
        {
            std::cout << "person: " << p->name << ", " << p->age << '\n';
        }
        else
        {
            std::cout << "not a person: " << j << '\n';
        }
    }
}
