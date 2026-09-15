#include <iostream>
#include <nlohmann/json.hpp>

int main()
{
    nlohmann::ordered_map<std::string, std::string> m;

    // emplace a new element
    auto res1 = m.emplace("one", "eins");
    std::cout << std::boolalpha << "inserted: " << res1.second << ", value: " << res1.first->second << std::endl;

    // emplace with an already-existing key: no-op, returns the existing element
    auto res2 = m.emplace("one", "uno");
    std::cout << std::boolalpha << "inserted: " << res2.second << ", value: " << res2.first->second << std::endl;
}
