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

    // call type_name()
    std::cout << j_null << " is a " << j_null.type_name() << '\n';
    std::cout << j_boolean << " is a " << j_boolean.type_name() << '\n';
    std::cout << j_number_integer << " is a " << j_number_integer.type_name() << '\n';
    std::cout << j_number_unsigned << " is a " << j_number_unsigned.type_name() << '\n';
    std::cout << j_number_float << " is a " << j_number_float.type_name() << '\n';
    std::cout << j_object << " is an " << j_object.type_name() << '\n';
    std::cout << j_array << " is an " << j_array.type_name() << '\n';
    std::cout << j_string << " is a " << j_string.type_name() << '\n';
}
