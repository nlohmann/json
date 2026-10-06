#include <iostream>
#include <nlohmann/json_view.hpp>
#include <string>
#include <vector>

using json_document = nlohmann::json_document;
using json_view = nlohmann::json_view;

// address has no direct conversion in get<T>(), so get<address>() falls back
// to materialize().get<address>() -- a real nlohmann::json value is built
// for just this one member, and its own from_json() runs on that
struct address
{
    std::string city;
    int zip = 0;
};

void from_json(const nlohmann::json& j, address& a)
{
    j.at("city").get_to(a.city);
    j.at("zip").get_to(a.zip);
}

int main()
{
    json_document doc = json_document::parse(R"(
      {
        "name": "Alice",
        "active": true,
        "orders": [1, 2, 3],
        "address": {"city": "Berlin", "zip": 10115}
      }
    )");
    const json_view customer = doc.root();

    // read typed fields straight into C++ variables -- none of these build
    // a nlohmann::json value
    const std::string name = customer["name"].get<std::string>();
    const bool active = customer["active"].get<bool>();
    std::cout << name << (active ? " (active)" : " (inactive)") << '\n';

    // std::vector<json_view> keeps views of the array elements instead of
    // copies of their values
    bool first = true;
    for (const json_view order : customer["orders"].get<std::vector<json_view>>())
    {
        std::cout << (first ? "" : " ") << order.get<int>();
        first = false;
    }
    std::cout << '\n';

    // everything else goes through materialize()
    const address a = customer["address"].get<address>();
    std::cout << a.city << ' ' << a.zip << '\n';
}
