#include <iostream>
#include <nlohmann/json.hpp>

int main()
{
    nlohmann::ordered_map<std::string, int> m;
    m["one"] = 1;

    auto it = m.find("one");
    if (it != m.end())
    {
        std::cout << "found: " << it->first << " = " << it->second << std::endl;
    }

    if (m.find("two") == m.end())
    {
        std::cout << "\"two\" not found" << std::endl;
    }
}
