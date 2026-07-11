#include <iostream>
#include <nlohmann/json.hpp>

int main()
{
    nlohmann::ordered_map<std::string, int> m;
    m["one"] = 1;
    m["two"] = 2;
    m["three"] = 3;

    // erase by key
    std::size_t removed = m.erase("two");
    std::cout << "removed by key: " << removed << std::endl;

    // erase by iterator
    m.erase(m.begin());

    std::cout << "remaining: ";
    for (const auto& element : m)
    {
        std::cout << element.first << ' ';
    }
    std::cout << std::endl;
}
