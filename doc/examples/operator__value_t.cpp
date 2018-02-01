#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    // create JSON values
    json j_null;
    json j_boolean = true;
    json j_number_integer = -17;
    json j_number_unsigned = 42u;
    json j_number_float = 23.42;
    json j_object = {{"one", 1}, {"two", 2}};
    json j_array = {1, 2, 4, 8, 16};
    json j_string = "Hello, world";

    // call operator value_t()
    json::value_t t_null = j_null;
    json::value_t t_boolean = j_boolean;
    json::value_t t_number_integer = j_number_integer;
    json::value_t t_number_unsigned = j_number_unsigned;
    json::value_t t_number_float = j_number_float;
    json::value_t t_object = j_object;
    json::value_t t_array = j_array;
    json::value_t t_string = j_string;

    // print types
    std::cout << std::boolalpha;
    std::cout << (t_null == json::value_t::null) << '\n';
    std::cout << (t_boolean == json::value_t::boolean) << '\n';
    std::cout << (t_number_integer == json::value_t::number_integer) << '\n';
    std::cout << (t_number_unsigned == json::value_t::number_unsigned) << '\n';
    std::cout << (t_number_float == json::value_t::number_float) << '\n';
    std::cout << (t_object == json::value_t::object) << '\n';
    std::cout << (t_array == json::value_t::array) << '\n';
    std::cout << (t_string == json::value_t::string) << '\n';
}
