#include <iostream>
#include "json.hpp"

using json = nlohmann::json;

int main()
{
    // create the different JSON values with default values
    json j_null(json::value_t::null);
    json j_boolean(json::value_t::boolean);
    json j_number_integer(json::value_t::number_integer);
    json j_number_float(json::value_t::number_float);
    json j_object(json::value_t::object);
    json j_array(json::value_t::array);
    json j_string(json::value_t::string);

    // serialize the JSON values
    std::cout << j_null << '\n';
    std::cout << j_boolean << '\n';
    std::cout << j_number_integer << '\n';
    std::cout << j_number_float << '\n';
    std::cout << j_object << '\n';
    std::cout << j_array << '\n';
    std::cout << j_string << '\n';
}
