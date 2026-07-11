#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    std::cout << std::boolalpha
              << std::is_same<json::json_sax_t::number_float_t, json::number_float_t>::value << std::endl;
}
