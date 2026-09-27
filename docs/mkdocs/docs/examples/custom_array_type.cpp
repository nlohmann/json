#include <iostream>
#include <map>

#include <nlohmann/json.hpp>

#include "custom_array_type.hpp"

using custom_json = nlohmann::basic_json<std::map, custom_array_type>;

int main()
{
    custom_json j = custom_json::array();
    j.push_back(1);
    j.push_back(2);
    j.push_back(3);

    std::cout << j.dump() << std::endl;
    std::cout << std::boolalpha << (custom_json::parse(j.dump()) == j) << std::endl;
}
