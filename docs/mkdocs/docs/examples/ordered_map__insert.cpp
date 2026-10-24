#include <iostream>
#include <nlohmann/json.hpp>

int main()
{
    nlohmann::ordered_map<std::string, int> m;

    // insert a single value
    auto res = m.insert({"one", 1});
    std::cout << std::boolalpha << "inserted: " << res.second << std::endl;

    // insert a range from another container
    std::vector<std::pair<const std::string, int>> more = {{"two", 2}, {"three", 3}};
    m.insert(more.begin(), more.end());

    for (const auto& element : m)
    {
        std::cout << element.first << ':' << element.second << ' ';
    }
    std::cout << std::endl;
}
