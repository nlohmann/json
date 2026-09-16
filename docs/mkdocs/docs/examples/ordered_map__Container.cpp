#include <iostream>
#include <nlohmann/json.hpp>

int main()
{
    using Map = nlohmann::ordered_map<std::string, int>;

    std::cout << std::boolalpha
              << "Container is std::vector<std::pair<const Key, T>>: "
              << std::is_same<Map::Container, std::vector<std::pair<const std::string, int>>>::value
              << std::endl;
}
