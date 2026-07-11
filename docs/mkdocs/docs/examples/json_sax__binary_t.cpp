#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    std::cout << std::boolalpha
              << std::is_same<json::json_sax_t::binary_t, json::binary_t>::value << std::endl;
}
