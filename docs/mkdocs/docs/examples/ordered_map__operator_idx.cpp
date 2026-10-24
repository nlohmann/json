#include <iostream>
#include <nlohmann/json.hpp>

int main()
{
    nlohmann::ordered_map<std::string, int> m;

    // operator[] inserts a default-constructed value if the key doesn't exist yet
    m["one"] = 1;
    std::cout << "m[\"one\"] = " << m["one"] << std::endl;

    // accessing again just returns the existing value
    std::cout << "m[\"one\"] = " << m["one"] << std::endl;
}
