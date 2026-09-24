#include <iostream>
#include <map>
#include <vector>

#include <nlohmann/json.hpp>

#include "custom_string_type.hpp"

using custom_json = nlohmann::basic_json<std::map, std::vector, custom_string_type>;

int main()
{
    custom_json j;
    j["pi"] = 3.141;
    j["happy"] = true;
    j["list"] = {1, 2, 3};

    std::cout << j.dump(2) << std::endl;
    std::cout << std::boolalpha << (custom_json::parse(j.dump()) == j) << std::endl;
}
